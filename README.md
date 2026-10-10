# secret-guard

**Claude Code mod · v1.3.1.** Detects specific credential patterns, blocks covered actions, and masks recognized secrets in textual results. It is not a universal scanner or a security boundary against adversarial code.

## Requirements

- Claude Code with mod support. Tested with **2.1.293 on Windows**; this is the tested engine version, not the mod version. Check yours with `claude --version`.
- The terminal or a local session in Claude Desktop's **Code** tab. These mods do not customize regular Claude chat. Desktop bundles its own engine; check `/status` there.
- Git for cloning and repository checks. No npm installation or build step is required to use the mod.
- The interface currently uses Spanish labels. This README is in English.

## Installation

### Try it for one session

Clone the repository, or download and extract its ZIP. Open a terminal **inside the secret-guard folder**, next to this README:

```shell
claude plugin validate .
claude --plugin-dir .
```

The first command checks the manifests and lists registered hooks and engine calls. The second starts a session with the mod. The dot means the current folder; use its absolute path when running from elsewhere.

### Install persistently

From the same folder, run in your terminal:

```shell
claude plugin marketplace add .
claude plugin install secret-guard@secret-guard --scope user
```

Start Claude Code, or run `/reload-plugins` in an existing session. Keep the local folder in place: the marketplace depends on it. The `user` scope applies to your account on this computer; `local` limits installation to the current project. Avoid loading an installed copy and another copy through `--plugin-dir` at the same time.

You can also install straight from GitHub, without cloning: run `claude plugin marketplace add pedrovelasquez9/secret-guard` instead of the first command. The marketplace name remains `secret-guard`. These instructions assume one repository per mod, with `.claude-plugin` at its root.

### Verify installation

Open `/plugin` in an interactive session and check that the mod is active. Run `/secret-guard` to open its panel. The command runs immediately, including during a turn. An installed, enabled mod loads automatically; opening its panel does not activate it.

In a disposable folder, ask: “Use Write to create demo.txt containing hello.” The call should appear as a passed check. Then ask: “Use Write to replace demo.txt with the literal text [REDACTED:stripe-secret].” The second call should be blocked and the original content retained. This checks interception and the panel without real credentials; automated tests exercise detection with synthetic values.

### Update or uninstall

After updating the local checkout, run:

```shell
claude plugin marketplace update secret-guard
claude plugin update secret-guard@secret-guard
```

Reload plugins in your session. Use `/plugin` to disable or uninstall the mod. When publishing code changes, increment the version in `.claude-plugin/plugin.json` so the update has a distinct version.

## Troubleshooting

1. Check the engine version and active mods in `/plugin`.
2. Confirm the selected directory contains `.claude-plugin/plugin.json` and `hooks/hooks.json`.
3. Reload plugins and try the manual panel command in a local session. Enlarge the window if space is limited.
4. Check whether safe mode, `disableAllHooks`, or organizational settings prevent mods from loading.

## What it checks

| Action | Scope |
| --- | --- |
| Write / Edit / NotebookEdit | New text, including unquoted assignments. Rejects redaction markers. A Git-ignored local environment file may contain recognized secrets, except public frontend variable names: `public-env-secret` still blocks them. |
| Bash / PowerShell | Literal command text; rejects recognized secrets and redaction markers. Uses the session's current directory, including after an earlier directory change. Quoted text (a commit message containing `;` or `|`) never splits the command. Commit/push wrapped in another command (`sh -c`, `env`, `xargs`…) is refused instead of skipped. Commands that change this mod's settings or installation are refused: those are a person's decision. |
| Commit | Staged diff by default. `-a` checks tracked working-tree changes, not new untracked files. Explicit paths are compared against HEAD; before the initial commit, stage changes and commit without explicit paths. |
| Recognized Git commands | Follows Bash and PowerShell forms: `&&`, `;` and new lines, `cd`/`Set-Location`, Git Bash paths (`/c/...`), `git -C`, `git -c key=value`, `& git`, `git.exe`, heredoc and here-string commit messages, and simple Git aliases. Read-only Git (status, log, diff, fetch…) is never inspected or blocked. A commit/push the parser cannot follow is refused with the reason, as are `-c` settings that change the destination (`remote.*`, `url.*`, `push.*`…), shell aliases beginning with !, forced git add, and several Git operations with commit/push in one call. Run operations separately so each actual state can be inspected. |
| Push | Queries refs advertised by the push destination and excludes its commits available locally. Checks history reachable from outgoing tips but absent from that set, including root commits and merges. History on another remote is not excluded. |
| Deploy | Checks tracked/unignored files and known build directories. Recognizes Vercel options/paths, npm/pnpm/yarn/bun publish, docker push, and other supported deployment forms. Does not reconstruct actual upload packaging or inspect container layers. |
| MCP / WebFetch | Scans serialized arguments without content-based exemptions. An allow marker in another field cannot disable scanning. |
| Results / attachments | Masks recognized text in tool results, tool messages, attachments and other hooks' context, including unquoted values. Complete private keys are masked through END; without END, only the header and consecutive recognizable base64 body lines are masked, preserving unrelated following text. |

Commit/push checks also flag added sensitive filenames: `.env` and local variants, `.dev.vars`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `.netrc`, `.pgpass`, `.htpasswd`, `credentials.json`, service-account/firebase-adminsdk JSON files, and `.p12`, `.pfx`, `.jks`, `.keystore`, and `.tfstate` files. A `.pub` public key is not blocked by that filename rule. Environment templates are exempt from filename classification, but their content is scanned.

## Allowing a rule (people only)

Some values are public by design, such as the `apiKey` in a Firebase web config. Its `google-api-key` rule would block writing that config, committing it, and deploying a bundle that contains it. A person can turn specific rules off in the plugin settings:

```shell
claude plugin install secret-guard@secret-guard --scope user --config allowedRules=google-api-key
```

You can also use the *Reglas permitidas* row in `/config`, or set `pluginConfigs["secret-guard"].options.allowedRules` in `~/.claude/settings.json`. The value is a comma-separated list of rule ids; unknown ids are ignored. An allowed rule is off everywhere: writes, commits, pushes, deploys, MCP/WebFetch and masking, and the generic entropy rules do not catch the same value again. Allow only what you have reviewed.

The mod refuses agent attempts to change this setting or to disable, uninstall or reinstall itself, both through shell commands and by writing settings files. This is best effort against a well-meaning agent, not a boundary against code that sets out to evade it.

Rule ids: `private-key`, `aws-access-key`, `aws-secret-key`, `github-token`, `gitlab-token`, `slack-token`, `slack-webhook`, `discord-webhook`, `stripe-secret`, `stripe-webhook`, `openai-key`, `anthropic-key`, `google-api-key`, `google-oauth-secret`, `huggingface-token`, `sendgrid-key`, `npm-token`, `supabase-secret`, `supabase-service-role`, `connection-string`, `bearer-token`, `public-env-secret`, `hardcoded-secret`, `env-secret`.

## Review panel

- Automatic opening after a block/error does not take focus and depends on available space. The manual command opens the panel immediately.
- `Última comprobación` means Latest check; `Ver historial` means View history. Shortcuts are `1` and `2` while focused, plus Tab/Enter where supported.
- Retains the latest 30 incidents (blocks, incomplete checks, masked results) plus the latest passed check, without storing credential values, commands, or file bodies. Routine passes never push an incident out of the history. A blocked or incomplete check states its reason in the conversation.
- Toasts report blocks and masked results. Display failures do not authorize a blocked action.
- `Comprobación superada` means the call passed this mod's checks, not that the tool succeeded or the entire project is safe.
- `/clear` or a new session resets history; closing the panel does not.

## Deliberate limits

- **No comment-based exceptions:** `secret-guard:allow` and `gitleaks:allow` do not disable detection or redaction. Exceptions live only in the `allowedRules` setting below, which a person changes; model-facing messages do not suggest bypasses.
- Push scans allow up to 500 candidate commits and 100 refs. Local Git commands time out after 30 seconds and the destination query after 20. If the destination cannot be queried (offline, an SSH key that needs a passphrase), the check falls back to the commits last fetched from that remote instead of failing: those were already public. Git never prompts for credentials (terminal or Credential Manager window) and runs with `core.fsmonitor`, external diff and textconv drivers off, so a repository's own config cannot run code during the check. Errors, truncation, or hook-budget exhaustion reject the check. No fetches or ref writes are performed. Querying the destination can require network access and authentication.
- `--all` selects local branches; `--tags` selects tags; `--mirror` selects all locally stored refs, including remote-tracking refs. Wildcards, multiple push URLs, custom remote.push mappings without explicit refs, and push.default=matching without explicit refs are rejected to avoid inspecting the wrong shipment.
- An empty destination requires checking initial history. Large histories require separate review or smaller operations. Advertised objects unavailable locally do not exclude history, so checks can be conservative.
- Deploy scans cap at 10,000 files and skip dependencies, internal directories, recognized binaries, and lockfiles. Local environment files are checked for public frontend variable names. Later-generated artifacts, container layers, and remote packaging are not covered.
- Shell recognition is a limited subset, not a Bash/PowerShell interpreter. Shell functions/aliases, wrapper scripts, dynamic substitutions, and unrecognized syntax remain outside coverage. Equivalent ways of invoking Git or deploying may not be detected.
- Heuristics can miss fragmented, encoded, low-entropy, or unknown formats. Edit does not reconstruct the whole file. User prompts, images, and manual operations are not protected.
- Revoke or rotate exposed credentials. Use repository/CI scanning and provider controls alongside this mod.

## Project layout

| File | Responsibility |
| --- | --- |
| `hooks/register.ts` | Engine-facing hooks and panel, Git/deploy inspection, and result redaction |
| `hooks/rules.ts` | Pure detection, redaction, diff scanning, and file classification |
| `hooks/commands.ts` | The supported Git command parser and deployment path selection |
| `hooks/panel-model.ts` | Sanitized event metadata, bounded history, and explanations |
| `types/index.d.ts` | Shared panel types and engine state declarations |
| `tests/` | Detection, parser, hook, and panel regression tests |

The engine validates access through `$` and `on` within a single hooks module. Engine-facing panel handlers therefore stay in `register.ts`; pure state and display logic live in `panel-model.ts`.

## Development

From **inside secret-guard**:

```shell
claude plugin validate .
claude plugin test .
node scripts/check-source.mjs
```

The source scanner requires **Node.js 24**; Node is not a separate runtime requirement for installing the mod. It prints findings without credential values and exits unsuccessfully if its own source matches a rule.

Claude Code 2.1.293 declarations and their TypeScript configuration are versioned in `.claude-plugin/types/`, except `claude-code-mcp/`: the engine generates it from the MCP connectors of the machine that loaded the mod, so it is private and git-ignored. The root `tsconfig.json` extends that copy. A clean checkout needs no declaration-generation step; regenerate and review compatibility when upgrading the engine.

Synthetic fixtures are assembled from fragments so the repository does not trigger its own guard. Tests include a positive case for every rule, the actual command parser, MCP/WebFetch, deployments containing matches, Git/cwd/aliases, redaction, display failures, and the panel. Release review also includes source scanning and disposable local Git repositories. Automated success does not establish universal secret detection.

## Compatibility and distribution

[Official mod documentation](https://code.claude.com/docs/en/plugins/mods/overview) · [Plugin documentation](https://code.claude.com/docs/en/plugins).

Engine APIs can change. Run validation and tests after upgrading Claude Code. Automated component rendering tests do not replace an interactive visual check. Other operating systems and engine versions have not been verified in this release review.

Released under the [MIT License](LICENSE). Repository: [github.com/pedrovelasquez9/secret-guard](https://github.com/pedrovelasquez9/secret-guard).
