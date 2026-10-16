---
name: microsandbox-docs
description: Edit Microsandbox product, CLI, and SDK documentation with verified behavior, concise examples, and the repository's Mintlify conventions. Use for changes under microsandbox/docs.
---

# Microsandbox docs

Follow the repository's `AGENTS.md` for contribution rules and SDK reference structure. Read the affected pages and check the working tree before editing. If a target branch is specified, start from its latest commit and preserve unrelated branch changes.

## Verify the feature

- Check implementation, configuration schema, CLI flags, and supported SDKs before naming an option or writing an example. Distinguish per-secret settings from sandbox-wide defaults and secret-policy denials from ordinary network denials.
- Check the published tag or release before attaching a version pill. A merged change is not evidence that a tagged version contains it. State local-only or cloud limitations only where they affect the documented workflow.
- Make examples internally complete. When an example expects a JSON HTTP denial response, show the response enablement, JSON format, and applicable message setting together, even if some are current defaults.

## Write the page

- Lead with what the reader can do and the shortest useful example. Put the main code sample on the page; use accordions for limits and secondary details.
- Use short headings that name the operation. Keep violation actions, host permissions such as placeholder passthrough, and response-message configuration conceptually separate.
- Use `CodeGroup` for supported language examples when a workflow spans SDKs. Show a CLI example only when an equivalent flag or command exists. Put `sandbox.yml` in a YAML configuration section instead of presenting it as a CLI command.
- Keep prose independent of language-specific syntax when possible. Put language or CLI details beside their example or in the relevant reference page. Preserve meaningful edge cases without repeating them across pages.

## Validate and deliver

- Run `python3 scripts/check-docs-language-order.py` and `git diff --check`. Parse changed YAML examples, check links and anchors, and load the affected pages in the Mintlify preview when available.
- Report the changed pages, checks, and any behavior or release ambiguity. Follow the user's requested target branch and publishing route.
