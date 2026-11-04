"""Safety boundaries for admission, fresh disks, credentials, and cleanup."""

from copy import deepcopy
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from clients import ApiError, GitHub
from controller import Controller, reap_expired_resources
from models import Config, Lease, candidate, utc
from wait_for_cleanup import cleanup_finished

NOW = 1_800_000_000
SCOPE = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-ci'
IMAGE = {'publisher': 'MicrosoftWindowsDesktop', 'offer': 'test', 'sku': 'test', 'version': '1.2.3'}
CFG = Config('example/project', 42, '00000000-0000-0000-0000-000000000000', 'test-ci', 'test-region',
             SCOPE + '/providers/Microsoft.Network/virtualNetworks/test/subnets/ci', 'ssh-ed25519 AAAA', '192.0.2.1/32',
             {'win10': IMAGE, 'win11': IMAGE})


def lease(**changes):
    return replace(Lease(100, 50, 2, 'win10', 'a' * 40, NOW, NOW + 3600), **changes)


def job_run(item=None):
    item = item or lease()
    run = {'id': item.run_id, 'run_attempt': item.attempt, 'head_sha': item.revision, 'workflow_id': 42,
           'path': '.github/workflows/check.yml', 'status': 'in_progress', 'event': 'pull_request',
           'head_repository': {'full_name': 'fork/project'}, 'created_at': utc(NOW)}
    job = {'id': item.job_id, 'run_id': item.run_id, 'status': 'queued', 'name': 'Windows WHP (10)', 'labels': item.labels}
    return run, job


class MemoryLeases:
    def __init__(self, *items):
        self.items = {item.job_id: deepcopy(item) for item in items}

    def list(self):
        return deepcopy(list(self.items.values()))

    def save(self, item):
        self.items[item.job_id] = deepcopy(item)

    def delete(self, item):
        del self.items[item.job_id]


class FakeAzure:
    def __init__(self, resources=None):
        self.resources = resources or {}
        self.calls = []

    def call(self, method, path, body=None, **options):
        self.calls.append((method, path, body))
        key = path.split('?')[0]
        if method == 'GET':
            if key.endswith('/resources') and key not in self.resources:
                return {'value': []}
            return deepcopy(self.resources.get(key))
        if method == 'DELETE':
            self.resources.pop(key, None)
        if method == 'PUT':
            self.resources[key] = deepcopy(body)
        return {}


class FakeGitHub:
    def __init__(self, status='in_progress', queued=()):
        self.status, self.candidates, self.completed, self.cancelled = status, queued, [], []
        self.jit_calls = 0

    def job(self, item):
        return {'status': self.status, 'conclusion': 'cancelled' if self.status == 'completed' else None}

    def queued(self):
        return iter(self.candidates)

    def create_check(self, item):
        return 999

    def complete_check(self, item):
        self.completed.append(deepcopy(item))

    def remove_runner(self, item):
        pass

    def cancel(self, item):
        self.cancelled.append(item.run_id)

    def jit(self, item):
        self.jit_calls += 1
        return {'runner': {'id': 123}, 'encoded_jit_config': 'SYNTHETIC_PRIVATE_CONFIG'}


class ControllerTests(unittest.TestCase):
    def test_approved_fork_is_bound_to_workflow_run_attempt_and_platform(self):
        run, job = job_run()
        self.assertEqual(job['labels'], ['msb-whp-50-2-win10'])
        self.assertIsNotNone(candidate(CFG, run, job, 'all_external_contributors', NOW))
        mutations = [('workflow_id', 43), ('status', 'action_required'), ('path', '.github/workflows/other.yml'), ('run_attempt', 3)]
        for key, value in mutations:
            with self.subTest(key=key):
                altered = {**run, key: value}
                self.assertIsNone(candidate(CFG, altered, job, 'all_external_contributors', NOW))
        self.assertIsNone(candidate(CFG, run, job, 'first_time_contributors', NOW))
        self.assertIsNone(candidate(CFG, run, {**job, 'labels': ['self-hosted']}, 'all_external_contributors', NOW))
        self.assertIsNone(candidate(CFG, run, {**job, 'name': 'arbitrary command'}, 'all_external_contributors', NOW))

    def test_private_configuration_rejects_broad_access_and_unpinned_images(self):
        for changes in ({'ssh_source': '0.0.0.0/0'}, {'capacity': 3}, {'lifetime': 7200},
                        {'subnet_id': '/subscriptions/another/network'},
                        {'images': {'win10': {**IMAGE, 'version': 'latest'}, 'win11': IMAGE}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(CFG, **changes)

    def test_vm_creation_always_uses_a_fresh_disk_and_has_no_identity(self):
        item = lease()
        vm, disk, nic, ip = item.resource_ids(CFG)
        azure = FakeAzure({ip: {'properties': {'provisioningState': 'Succeeded'}}, nic: {'properties': {'provisioningState': 'Succeeded'}}})
        store = MemoryLeases(item)
        Controller(CFG, azure, FakeGitHub(), store).create(item)
        body = next(body for method, path, body in azure.calls if method == 'PUT' and path == vm)
        self.assertNotIn('identity', body)
        self.assertEqual(body['properties']['storageProfile']['osDisk']['createOption'], 'FromImage')
        self.assertEqual(body['properties']['storageProfile']['osDisk']['deleteOption'], 'Delete')
        self.assertNotIn(body['properties']['osProfile']['adminPassword'], json.dumps(store.items[100].to_dict()))

    def test_cleanup_is_verified_before_reporting_success(self):
        item = lease(phase='running', check_id=1)
        azure = FakeAzure({resource: {} for resource in item.resource_ids(CFG)})
        github = FakeGitHub(status='completed')
        store = MemoryLeases(item)
        controller = Controller(CFG, azure, github, store, lambda: NOW)
        controller.tick()
        self.assertFalse(github.completed)
        self.assertEqual(store.items[100].phase, 'cleanup')
        controller.tick()
        self.assertFalse(store.items)
        self.assertEqual(len(github.completed), 1)
        self.assertFalse(github.cancelled)  # Completed test jobs do not cancel other platforms.

    def test_expiry_destroys_resources_even_with_admission_disabled_and_github_down(self):
        item = lease(phase='running')
        azure = FakeAzure({resource: {} for resource in item.resource_ids(CFG)})
        class OfflineGitHub(FakeGitHub):
            def job(self, item):
                raise AssertionError('GitHub must not be needed for expiry')
            def remove_runner(self, item):
                raise ApiError(503)
        store = MemoryLeases(item)
        controller = Controller(CFG, azure, OfflineGitHub(), store, lambda: NOW + 3601)
        controller.tick()
        self.assertFalse(azure.resources)
        self.assertEqual(store.items[100].conclusion, 'timed_out')
        controller.tick()
        self.assertFalse(azure.resources)

    def test_global_capacity_does_not_create_another_lease(self):
        existing = lease(phase='running', check_id=1)
        new = lease(job_id=101, run_id=51)
        run, job = job_run(new)
        store = MemoryLeases(existing)
        Controller(replace(CFG, enabled=True, capacity=1), FakeAzure(), FakeGitHub(queued=[(run, job, 'all_external_contributors')]), store, lambda: NOW).tick()
        self.assertEqual(set(store.items), {100})

    def test_jit_secret_is_only_a_protected_command_parameter(self):
        item = lease(phase='jit')
        store, azure, github = MemoryLeases(item), FakeAzure(), FakeGitHub()
        Controller(CFG, azure, github, store, lambda: NOW).advance(item)
        self.assertNotIn('SYNTHETIC_PRIVATE_CONFIG', json.dumps(store.items[100].to_dict()))
        body = next(body for method, path, body in azure.calls if method == 'PUT')
        self.assertEqual(body['properties']['protectedParameters'][0]['value'], 'SYNTHETIC_PRIVATE_CONFIG')
        self.assertNotIn('parameters', body['properties'])
        self.assertEqual(store.items[100].phase, 'jit-staged')
        self.assertFalse(any('Start-Service' in json.dumps(call) for call in azure.calls))

    def test_recovery_does_not_reissue_a_staged_jit_configuration(self):
        item = lease(phase='jit', runner_id=123)
        path = item.resource_ids(CFG)[0] + '/runCommands/credentials'
        azure, github, store = FakeAzure({path: {}}), FakeGitHub(), MemoryLeases(item)
        Controller(CFG, azure, github, store, lambda: NOW).advance(item)
        self.assertEqual(github.jit_calls, 0)
        self.assertEqual(store.items[100].phase, 'jit-staged')

    def test_orphan_expiry_is_tagged_scoped_and_independent_of_lease_storage(self):
        item = lease()
        resource = {'type': 'Microsoft.Network/networkInterfaces', 'name': item.name + '-nic',
                    'id': item.resource_ids(CFG)[2], 'tags': item.tags}
        foreign = {**resource, 'id': resource['id'].replace('/test-ci/', '/not-ours/')}
        untagged = {**resource, 'tags': {}}
        fresh = {**resource, 'tags': {**item.tags, 'expires-at': utc(NOW + 7200)}}
        azure = FakeAzure({CFG.scope + '/resources': {'value': [resource, foreign, untagged, fresh]}})
        reap_expired_resources(CFG, azure, NOW + 3601)
        self.assertEqual([path for method, path, body in azure.calls if method == 'DELETE'], [resource['id']])

    def test_queue_deadline_cancels_only_the_owned_run(self):
        run, job = job_run()
        run['created_at'] = utc(NOW - 6000)
        github, store = FakeGitHub(queued=[(run, job, 'all_external_contributors')]), MemoryLeases()
        Controller(replace(CFG, enabled=True), FakeAzure(), github, store, lambda: NOW).tick()
        self.assertEqual(github.cancelled, [50])
        self.assertFalse(store.items)
        self.assertEqual(github.completed[0].conclusion, 'timed_out')

    def test_upstream_build_time_does_not_consume_a_known_job_queue_deadline(self):
        run, job = job_run()
        run['created_at'] = utc(NOW - 6000)
        job['started_at'] = utc(NOW)
        github, store = FakeGitHub(queued=[(run, job, 'all_external_contributors')]), MemoryLeases()
        Controller(replace(CFG, enabled=True), FakeAzure(), github, store, lambda: NOW).tick()
        self.assertFalse(github.cancelled)
        self.assertEqual(set(store.items), {job['id']})

    def test_cleanup_requires_both_exact_attempts_and_the_controller_app(self):
        expected = {'windows-whp/50/2/win10', 'windows-whp/50/2/win11'}
        checks = [{'id': index, 'external_id': identity, 'app': {'id': 42},
                   'status': 'completed', 'conclusion': 'success'} for index, identity in enumerate(sorted(expected))]
        self.assertTrue(cleanup_finished(checks, 42, expected))
        self.assertFalse(cleanup_finished(checks[:1], 42, expected))
        self.assertFalse(cleanup_finished(checks, 43, expected))
        self.assertFalse(cleanup_finished(checks, 42, {'windows-whp/50/3/win10'}))
        checks[0]['status'] = 'in_progress'
        self.assertFalse(cleanup_finished(checks, 42, expected))
        checks[0].update(status='completed', conclusion='failure')
        with self.assertRaises(RuntimeError):
            cleanup_finished(checks, 42, expected)

    def test_orphan_cloud_resources_reserve_capacity_after_lease_loss(self):
        run, job = job_run(lease(job_id=101))
        azure = FakeAzure({CFG.scope + '/resources': {'value': [{'tags': lease().tags}]}})
        store = MemoryLeases()
        Controller(replace(CFG, enabled=True, capacity=1), azure,
                   FakeGitHub(queued=[(run, job, 'all_external_contributors')]), store, lambda: NOW).tick()
        self.assertFalse(store.items)

    def test_deleted_workflow_does_not_strand_runner_cleanup(self):
        api = GitHub(CFG, lambda: 'synthetic-token')
        for status in (404, 409):
            with self.subTest(status=status), patch.object(api, 'call', side_effect=ApiError(status)):
                api.cancel(lease())
        with patch.object(api, 'call', side_effect=ApiError(503)), self.assertRaises(ApiError):
            api.cancel(lease())

    def test_listener_stays_stopped_until_credential_command_is_gone(self):
        item = lease(phase='clear-credentials', runner_id=123)
        path = item.resource_ids(CFG)[0] + '/runCommands/credentials'
        azure, store = FakeAzure({path: {}}), MemoryLeases(item)
        controller = Controller(CFG, azure, FakeGitHub(), store, lambda: NOW)
        controller.advance(item)
        self.assertEqual(item.phase, 'clear-credentials')
        self.assertFalse(any(method == 'PUT' for method, _, _ in azure.calls))
        controller.advance(item)
        self.assertEqual(item.phase, 'start')
        self.assertFalse(any(method == 'PUT' for method, _, _ in azure.calls))


if __name__ == '__main__':
    unittest.main()
