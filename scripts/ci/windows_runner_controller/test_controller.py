"""Safety boundaries for admission, fresh disks, credentials, and cleanup."""

from copy import deepcopy
from contextlib import nullcontext
from dataclasses import replace
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from clients import ApiError, GitHub, attempt_jobs
from controller import Controller, reap_expired_resources
from models import Config, Lease, candidate, utc
from wait_for_cleanup import cleanup_finished, cleanup_expectations

NOW = 1_800_000_000
SCOPE = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-ci'
IMAGE = {'publisher': 'MicrosoftWindowsDesktop', 'offer': 'test', 'sku': 'test', 'version': '1.2.3'}
PREPARED_IMAGE = {'id': SCOPE + '/providers/Microsoft.Compute/galleries/test/images/windows/versions/1.0.0'}
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
    def test_attempt_job_pagination_is_complete_and_fails_closed_at_its_limit(self):
        records = [{'id': index} for index in range(65)]

        def response(method, path):
            self.assertIn('/runs/50/attempts/2/jobs?', path)
            query = parse_qs(urlsplit(path).query)
            size, page = int(query['per_page'][0]), int(query['page'][0])
            return {'jobs': records[(page - 1) * size:page * size]}

        self.assertEqual(attempt_jobs(response, 50, 2), records)
        with self.assertRaises(RuntimeError):
            attempt_jobs(lambda method, path: {'jobs': records[:30]}, 50, 2)

    def test_discovery_reserves_both_queued_platforms_and_deduplicates_runs(self):
        first, second = lease(), lease(job_id=101, platform='win11')
        run, job = job_run(first)
        run.update(status='queued', conclusion=None, head_repository={'full_name': CFG.repository})
        other_job = {**job, 'id': second.job_id, 'name': 'Windows WHP (11)', 'labels': second.labels}
        api, queried_states = GitHub(CFG, lambda: 'synthetic-token'), []

        def response(method, path, *args, **kwargs):
            self.assertEqual(method, 'GET')
            if path.endswith('fork-pr-contributor-approval'):
                return {'approval_policy': 'all_external_contributors'}
            if '/workflows/' in path:
                state = parse_qs(urlsplit(path).query)['status'][0]
                queried_states.append(state)
                # The same run may appear in both snapshots during a transition.
                return {'workflow_runs': [{**run, 'status': state}]}
            self.assertIn('/runs/50/attempts/2/jobs?', path)
            return {'jobs': [job, other_job]}

        with patch.object(api, 'call', side_effect=response):
            candidates = list(api.queued())
        self.assertEqual(set(queried_states), {'queued', 'in_progress'})
        self.assertEqual([entry[1]['id'] for entry in candidates], [100, 101])

        # Reproduce the actual stall: the only workflow snapshot is queued,
        # with both Windows jobs waiting and no existing runner lease.
        def queued_only(method, path, *args, **kwargs):
            if '/workflows/' in path and 'status=in_progress' in path:
                return {'workflow_runs': []}
            return response(method, path, *args, **kwargs)

        store = MemoryLeases()
        with patch.object(api, 'call', side_effect=queued_only):
            Controller(replace(CFG, enabled=True), FakeAzure(), api, store, lambda: NOW).tick()
        self.assertEqual(set(store.items), {100, 101})
        self.assertEqual({item.platform for item in store.items.values()}, {'win10', 'win11'})

    def test_discovery_finds_older_jobs_on_both_states_later_pages(self):
        first, second = lease(), lease(job_id=101, run_id=51, platform='win11')
        run, job = job_run(first)
        run.update(status='queued', conclusion=None, head_repository={'full_name': CFG.repository})
        other_run = {**run, 'id': second.run_id, 'status': 'in_progress'}
        other_job = {**job, 'id': second.job_id, 'run_id': second.run_id,
                     'name': 'Windows WHP (11)', 'labels': second.labels}
        batches = {
            'queued': [{**run, 'id': index} for index in range(1000, 1100)],
            'in_progress': [{**other_run, 'id': index} for index in range(2000, 2100)],
        }
        # Overlap can occur within pages and across the two state snapshots.
        batches['queued'] += [batches['queued'][-1], run]
        batches['in_progress'] += [other_run, {**run, 'status': 'in_progress'}]
        api, pages, inspected = GitHub(CFG, lambda: 'synthetic-token'), [], []

        def response(method, path, *args, **kwargs):
            self.assertEqual(method, 'GET')
            if path.endswith('fork-pr-contributor-approval'):
                return {'approval_policy': 'all_external_contributors'}
            query = parse_qs(urlsplit(path).query)
            if '/workflows/' in path:
                state, page = query['status'][0], int(query.get('page', ['1'])[0])
                size = int(query['per_page'][0])
                pages.append((state, page))
                return {'workflow_runs': batches[state][(page - 1) * size:page * size]}
            run_id = int(urlsplit(path).path.split('/')[3])
            inspected.append(run_id)
            return {'jobs': {50: [job], 51: [other_job]}.get(run_id, [])}

        with patch.object(api, 'call', side_effect=response):
            candidates = list(api.queued())
        self.assertEqual([entry[1]['id'] for entry in candidates], [100, 101])
        self.assertEqual(pages, [('queued', 1), ('queued', 2), ('in_progress', 1), ('in_progress', 2)])
        self.assertEqual(inspected, [50, 51, *range(1000, 1100), *range(2000, 2100)])

        # A later-page job must reach both normal admission and the deadline
        # path; simply listing it without enforcing its timeout is not enough.
        for age in (0, CFG.queue_timeout):
            with self.subTest(age=age):
                pending = [(r, {**j, 'created_at': utc(NOW - age)}, policy) for r, j, policy in candidates]
                github, store = FakeGitHub(queued=pending), MemoryLeases()
                Controller(replace(CFG, enabled=True), FakeAzure(), github, store, lambda: NOW).tick()
                if age:
                    self.assertFalse(store.items)
                    self.assertEqual(github.cancelled, [50, 51])
                    self.assertEqual([item.conclusion for item in github.completed], ['timed_out', 'timed_out'])
                else:
                    self.assertEqual(set(store.items), {100, 101})
                    self.assertFalse(github.cancelled)

    def test_discovery_checks_the_page_after_an_exactly_full_page(self):
        run, _ = job_run()
        run['head_repository'] = {'full_name': CFG.repository}
        records = [{**run, 'id': index} for index in range(100)]
        api, pages = GitHub(CFG, lambda: 'synthetic-token'), []

        def response(method, path, *args, **kwargs):
            if path.endswith('fork-pr-contributor-approval'):
                return {'approval_policy': 'all_external_contributors'}
            if '/workflows/' in path:
                query = parse_qs(urlsplit(path).query)
                state, page = query['status'][0], int(query.get('page', ['1'])[0])
                pages.append((state, page))
                return {'workflow_runs': records if state == 'queued' and page == 1 else []}
            return {'jobs': []}

        with patch.object(api, 'call', side_effect=response):
            self.assertEqual(list(api.queued()), [])
        self.assertEqual(pages, [('queued', 1), ('queued', 2), ('in_progress', 1)])

    def test_discovery_does_not_admit_jobs_from_an_incomplete_workflow_scan(self):
        run, _ = job_run()
        for state in ('queued', 'in_progress'):
            for failure in ('api', 'limit'):
                with self.subTest(state=state, failure=failure):
                    api, pages = GitHub(CFG, lambda: 'synthetic-token'), []

                    def response(method, path, *args, **kwargs):
                        if path.endswith('fork-pr-contributor-approval'):
                            return {'approval_policy': 'all_external_contributors'}
                        self.assertIn('/workflows/', path)  # No job is inspected before the scan completes.
                        query = parse_qs(urlsplit(path).query)
                        if query['status'][0] != state:
                            return {'workflow_runs': []}
                        page = int(query.get('page', ['1'])[0])
                        pages.append(page)
                        if failure == 'api' and page == 2:
                            raise ApiError(503)
                        return {'workflow_runs': [{**run, 'id': page * 100 + index} for index in range(100)]}

                    error = ApiError if failure == 'api' else RuntimeError
                    with patch.object(api, 'call', side_effect=response), self.assertRaises(error):
                        next(api.queued())
                    self.assertEqual(pages, [1, 2] if failure == 'api' else list(range(1, 11)))

    def test_queued_admission_rejects_approval_waits_and_invalid_identity(self):
        run, job = job_run()
        run.update(status='queued', conclusion=None)
        self.assertIsNotNone(candidate(CFG, run, job, 'all_external_contributors', NOW))
        for status in ('action_required', 'waiting', 'requested', 'pending', 'completed'):
            with self.subTest(status=status):
                self.assertIsNone(candidate(CFG, {**run, 'status': status}, job, 'all_external_contributors', NOW))
        for key, value in [('conclusion', 'action_required'), ('conclusion', 'cancelled'),
                           ('workflow_id', 43), ('event', 'pull_request_target'), ('run_attempt', 3)]:
            with self.subTest(key=key, value=value):
                self.assertIsNone(candidate(CFG, {**run, key: value}, job, 'all_external_contributors', NOW))
        self.assertIsNone(candidate(CFG, run, job, 'first_time_contributors', NOW))
        self.assertIsNone(candidate(CFG, run, {**job, 'labels': ['self-hosted']}, 'all_external_contributors', NOW))

    def test_fork_discovery_requires_the_same_attempts_successful_hosted_build(self):
        run, job = job_run()
        run.update(status='queued', conclusion=None)
        build = {'name': 'Build Windows CLI (windows-x86_64)', 'status': 'completed', 'conclusion': 'success',
                 'run_id': run['id'], 'head_sha': run['head_sha'], 'runner_id': 1, 'labels': ['windows-latest']}
        api = GitHub(CFG, lambda: 'synthetic-token')

        def discover(prerequisites):
            def response(method, path, *args, **kwargs):
                if path.endswith('fork-pr-contributor-approval'):
                    return {'approval_policy': 'all_external_contributors'}
                if '/workflows/' in path:
                    return {'workflow_runs': [run] if 'status=queued' in path else []}
                self.assertIn('/runs/50/attempts/2/jobs?', path)
                return {'jobs': [job, *prerequisites]}
            with patch.object(api, 'call', side_effect=response):
                return list(api.queued())

        self.assertFalse(discover([]))
        self.assertEqual(len(discover([build])), 1)
        # GitHub copies successful jobs into a partial rerun's attempt-specific
        # list, retaining their earlier execution timestamps. They still prove
        # approval for this exact run and revision, without rerunning the build.
        reused = {**build, 'id': 200, 'run_attempt': 2,
                  'started_at': utc(NOW - 7200), 'completed_at': utc(NOW - 3600)}
        self.assertEqual(len(discover([reused])), 1)
        for key, value in [('status', 'queued'), ('conclusion', 'skipped'), ('conclusion', 'failure'),
                           ('run_id', 51), ('head_sha', 'b' * 40), ('runner_id', 0),
                           ('labels', ['self-hosted']), ('name', 'unrelated build')]:
            with self.subTest(key=key, value=value):
                self.assertFalse(discover([{**build, key: value}]))

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

    def test_prepared_images_are_pinned_versions_in_the_dedicated_group(self):
        configured = replace(CFG, images={'win10': PREPARED_IMAGE, 'win11': PREPARED_IMAGE})
        self.assertTrue(configured.prepared_image(PREPARED_IMAGE))
        for image in (
            {'id': PREPARED_IMAGE['id'].replace('/test-ci/', '/unrelated/')},
            {'id': PREPARED_IMAGE['id'].replace('/1.0.0', '/latest')},
            {'id': PREPARED_IMAGE['id'] + '?version=1.0.0'},
            {'id': SCOPE + '/providers/Microsoft.Compute/disks/old-job'},
            {'id': SCOPE + '/providers/Microsoft.Compute/snapshots/old-job'},
            {**PREPARED_IMAGE, 'version': '1.0.0'},
        ):
            with self.subTest(image=image), self.assertRaises(ValueError):
                replace(CFG, images={'win10': image, 'win11': IMAGE})

    def test_image_rollout_uses_the_vms_actual_image_for_setup(self):
        configured = replace(CFG, images={'win10': PREPARED_IMAGE, 'win11': PREPARED_IMAGE})
        for actual, expected in ((IMAGE, 'bootstrap'), (PREPARED_IMAGE, 'prepare')):
            with self.subTest(expected=expected):
                item = lease()
                vm = {'properties': {'storageProfile': {'imageReference': actual}}}
                azure, store = FakeAzure({item.resource_ids(CFG)[0]: vm}), MemoryLeases(item)
                controller = Controller(configured, azure, FakeGitHub(), store, lambda: NOW)
                with patch.object(controller, 'create', return_value=True), \
                     patch.object(controller, 'command', return_value=False) as command, \
                     patch('controller.FILES') as files:
                    files.__truediv__.return_value.read_bytes.return_value = b'fixture'
                    files.__truediv__.return_value.read_text.return_value = 'fixture'
                    controller.advance(item)
                self.assertEqual(item.phase, expected)
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[1], expected)
                if expected == 'prepare':
                    self.assertEqual(command.call_args.args[3]['ImagePlatform'], 'win10')
                    self.assertIn('Probe', command.call_args.args[3])
                self.assertFalse(any(method == 'POST' for method, _, _ in azure.calls))

    def test_prepared_image_still_creates_a_new_disk_without_identity(self):
        configured = replace(CFG, images={'win10': PREPARED_IMAGE, 'win11': PREPARED_IMAGE})
        item = lease()
        vm, disk, nic, ip = item.resource_ids(configured)
        azure = FakeAzure({ip: {'properties': {'provisioningState': 'Succeeded'}},
                           nic: {'properties': {'provisioningState': 'Succeeded'}}})
        Controller(configured, azure, FakeGitHub(), MemoryLeases(item), lambda: NOW).create(item)
        body = next(body for method, path, body in azure.calls if method == 'PUT' and path == vm)
        self.assertEqual(body['properties']['storageProfile']['imageReference'], PREPARED_IMAGE)
        self.assertEqual(body['properties']['storageProfile']['osDisk']['createOption'], 'FromImage')
        self.assertEqual(body['properties']['storageProfile']['osDisk']['deleteOption'], 'Delete')
        self.assertNotIn('identity', body)

    def test_ready_transitions_are_persisted_before_starting_the_listener(self):
        item = lease(phase='clear-credentials', runner_id=123)
        store = MemoryLeases(item)
        controller = Controller(CFG, FakeAzure(), FakeGitHub(), store, lambda: NOW)

        def command(current, name, script):
            self.assertEqual(name, 'start')
            self.assertEqual(store.items[current.job_id].phase, 'start')
            return True

        with patch.object(controller, 'command', side_effect=command) as start:
            controller.advance(item)
        start.assert_called_once()
        self.assertEqual(store.items[item.job_id].phase, 'running')

    def test_setup_yields_on_pending_work_and_retains_the_legacy_reboot_guard(self):
        for phase in ('bootstrap', 'wait-reboot'):
            with self.subTest(phase=phase):
                item = lease(phase=phase, ready_after=NOW + 90)
                controller = Controller(CFG, FakeAzure(), FakeGitHub(), MemoryLeases(item), lambda: NOW)
                with patch.object(controller, 'command', return_value=False) as command, \
                     patch.object(controller, 'ready', return_value=True) as ready, patch('controller.FILES'):
                    controller.advance(item)
                self.assertEqual(item.phase, phase)
                self.assertEqual(command.call_count, 1 if phase == 'bootstrap' else 0)
                ready.assert_not_called()

    def test_setup_checks_expiry_between_immediate_transitions(self):
        item = lease(phase='clear-credentials')
        store = MemoryLeases(item)
        with patch('time.time', side_effect=[NOW, NOW + 3601]) as clock:
            controller = Controller(CFG, FakeAzure(), FakeGitHub(), store, clock)
            with patch.object(controller, 'command') as command:
                controller.advance(item)
        command.assert_not_called()
        self.assertEqual(store.items[item.job_id].phase, 'cleanup')
        self.assertEqual(store.items[item.job_id].conclusion, 'timed_out')

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

    def test_jit_recovery_removes_registration_when_response_or_save_is_lost(self):
        for failure in ('response', 'save'):
            with self.subTest(failure=failure):
                item = lease(phase='jit')
                store, azure, api = MemoryLeases(item), FakeAzure(), GitHub(CFG, lambda: 'synthetic-token')
                runners, created, deleted = {900: {'id': 900, 'name': 'wci-1000'}}, [], []

                def response(method, path, body=None, **options):
                    if path.startswith('/actions/runners?'):
                        return {'runners': list(runners.values())}
                    if path == '/actions/runners/generate-jitconfig':
                        runner = {'id': 300 + len(created), 'name': body['name']}
                        runners[runner['id']] = runner
                        created.append(runner['id'])
                        if failure == 'response' and len(created) == 1:
                            raise ApiError(504)  # The POST succeeded, but its response was lost.
                        return {'runner': runner, 'encoded_jit_config': 'SYNTHETIC_PRIVATE_CONFIG'}
                    runner_id = int(path.rsplit('/', 1)[1])
                    if method == 'DELETE':
                        deleted.append(runner_id)
                        runners.pop(runner_id, None)
                        return {}
                    return runners.get(runner_id)

                controller = Controller(CFG, azure, api, store, lambda: NOW)
                with patch.object(api, 'call', side_effect=response):
                    lost_save = patch.object(store, 'save', side_effect=RuntimeError('lost save')) if failure == 'save' else nullcontext()
                    with lost_save:
                        with self.assertRaises((ApiError, RuntimeError)):
                            controller.advance(item)
                    self.assertEqual(store.items[100].runner_id, 0)
                    self.assertIn(300, runners)
                    controller.advance(store.list()[0])
                self.assertIn(300, deleted)
                self.assertEqual(set(runners), {301, 900})
                self.assertEqual(store.items[100].runner_id, 301)
                self.assertEqual(store.items[100].phase, 'jit-staged')

    def test_cleanup_waits_for_unsaved_runner_removal(self):
        item = lease(phase='cleanup', check_id=1)
        store, api = MemoryLeases(item), GitHub(CFG, lambda: 'synthetic-token')
        runner = {'id': 300, 'name': item.name}
        runners, completed, deletes = {300: runner}, [], []

        def response(method, path, body=None, **options):
            if path.startswith('/actions/runners?'):
                return {'runners': list(runners.values())}
            if path == '/actions/runners/300':
                if method == 'DELETE':
                    deletes.append(300)
                    if len(deletes) == 1:
                        raise ApiError(503)
                    runners.clear()
                    return {}
                return runners.get(300)
            if path == '/check-runs/1':
                completed.append(body)
                return {}
            self.fail('Unexpected GitHub operation')

        controller = Controller(CFG, FakeAzure(), api, store, lambda: NOW)
        with patch.object(api, 'call', side_effect=response):
            controller.tick()
            self.assertFalse(completed)
            self.assertIn(100, store.items)
            controller.tick()
        self.assertFalse(runners)
        self.assertFalse(store.items)
        self.assertEqual(len(completed), 1)

    def test_runner_reconciliation_paginates_and_uses_exact_names(self):
        api, item = GitHub(CFG, lambda: 'synthetic-token'), lease()
        runners = {index: {'id': index, 'name': f'unrelated-{index}'} for index in range(1, 101)}
        runners.update({300: {'id': 300, 'name': item.name}, 301: {'id': 301, 'name': item.name + '0'}})
        deleted = []

        def response(method, path, *args, **options):
            if path.startswith('/actions/runners?'):
                page = int(parse_qs(urlsplit(path).query)['page'][0])
                return {'runners': list(runners.values())[(page - 1) * 100:page * 100]}
            runner_id = int(path.rsplit('/', 1)[1])
            if method == 'DELETE':
                deleted.append(runner_id)
                runners.pop(runner_id, None)
                return {}
            return runners.get(runner_id)

        with patch.object(api, 'call', side_effect=response):
            api.remove_runner(item)
        self.assertEqual(deleted, [300])
        self.assertIn(301, runners)

    def test_runner_reconciliation_requires_verified_absence(self):
        api, item = GitHub(CFG, lambda: 'synthetic-token'), lease(runner_id=300)

        def response(method, path, *args, **options):
            if path.startswith('/actions/runners?'):
                return {'runners': [{'id': 300, 'name': item.name}]}
            if method == 'GET':
                return {'id': 300, 'name': item.name}
            return {}  # Acknowledged DELETE, but removal has not completed.

        with patch.object(api, 'call', side_effect=response), self.assertRaises(RuntimeError):
            api.remove_runner(item)

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

    def test_partial_rerun_cleanup_uses_each_lanes_executed_attempt(self):
        jobs = [{'id': 100 + platform, 'run_id': 50, 'head_sha': 'a' * 40, 'run_attempt': 2,
                 'name': f'Windows WHP ({platform})', 'status': 'completed', 'conclusion': 'success',
                 'labels': [f'msb-whp-50-{attempt}-win{platform}']}
                for platform, attempt in ((10, 1), (11, 2))]
        expected = cleanup_expectations(jobs, 50, 2, 'a' * 40)
        self.assertEqual(expected, {'windows-whp/50/1/win10', 'windows-whp/50/2/win11'})
        checks = [{'id': index, 'external_id': identity, 'app': {'id': 42},
                   'status': 'completed', 'conclusion': 'success'} for index, identity in enumerate(sorted(expected))]
        self.assertTrue(cleanup_finished(checks, 42, expected))
        checks[1]['external_id'] = 'windows-whp/50/1/win11'
        self.assertFalse(cleanup_finished(checks, 42, expected))
        # Rerunning only the cleanup job reuses both original lane results.
        self.assertEqual(cleanup_expectations(jobs, 50, 3, 'a' * 40), expected)

    def test_cleanup_rejects_missing_skipped_or_mismatched_lane_identity(self):
        jobs = [{'run_id': 50, 'head_sha': 'a' * 40, 'name': f'Windows WHP ({platform})',
                 'status': 'completed', 'conclusion': 'success', 'labels': [f'msb-whp-50-2-win{platform}']}
                for platform in (10, 11)]
        for key, value in [('run_id', 51), ('head_sha', 'b' * 40), ('status', 'queued'),
                           ('conclusion', 'skipped'), ('labels', ['msb-whp-51-2-win10']),
                           ('labels', ['msb-whp-50-3-win10']), ('labels', ['msb-whp-50-2-win11']),
                           ('labels', ['msb-whp-50-2-win10', 'self-hosted'])]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                cleanup_expectations([{**jobs[0], key: value}, jobs[1]], 50, 2, 'a' * 40)
        for invalid in (jobs[:1], jobs + [jobs[0]], [{**jobs[0], 'conclusion': 'failure', 'labels': ['msb-whp-50-1-win10']}, jobs[1]]):
            with self.assertRaises(ValueError):
                cleanup_expectations(invalid, 50, 2, 'a' * 40)

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
        # Absence is now confirmed before starting in the same tick; an extra
        # minute-long wait after the successful GET adds no isolation guarantee.
        puts = [index for index, (method, _, _) in enumerate(azure.calls) if method == 'PUT']
        self.assertEqual(len(puts), 1)
        self.assertEqual(azure.calls[puts[0]][1], item.resource_ids(CFG)[0] + '/runCommands/start')
        self.assertIn(('GET', path, None), azure.calls[:puts[0]])


if __name__ == '__main__':
    unittest.main()
