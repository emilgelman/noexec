# Community Launch Posts

Use these templates when launching noexec on various platforms.

## HackerNews "Show HN" Post

**Best timing:** Weekday morning, 9-11am Pacific Time

**Title (max 80 chars):**
```
Show HN: noexec – Runtime security for AI coding assistants
```

**URL:**
```
https://github.com/emilgelman/noexec
```

**First Comment (post immediately after submission):**
```
Hi HN!

I built noexec to solve a problem I noticed with AI coding assistants: they can accidentally run dangerous commands or leak credentials.

Examples of what it blocks:
- echo $AWS_SECRET_ACCESS_KEY (credential leak)
- rm -rf / (destructive command)
- git push --force origin main (dangerous git operation)

How it works:
- Uses CLI hooks (like Claude Code's PreToolUse hook)
- Analyzes commands before execution
- Blocks if security issue detected
- Runs entirely locally (no network calls)

The tool is open source (MIT) with 5 built-in detectors. Currently supports Claude Code, with GitHub Copilot CLI coming soon.

I'd love feedback on:
1. What other dangerous patterns should be detected?
2. Which AI coding assistants do you use?
3. Would your team find this useful?

GitHub: https://github.com/emilgelman/noexec
npm: npm install -g noexec

Happy to answer any questions!
```

**Tips for HN engagement:**
- Monitor comments for first 2-4 hours
- Reply to ALL comments (positive and negative)
- Be humble, not defensive
- If someone suggests improvements, thank them and add to roadmap
- If someone reports a bug, acknowledge immediately
- Focus on technical details in responses

---

## Reddit r/programming

**Title:**
```
I built a security scanner for AI coding assistants (open source)
```

**Post type:** Link post

**URL:** https://github.com/emilgelman/noexec

**Comment on your own post:**
```
Hey r/programming!

I've been using Claude Code and other AI coding assistants, and realized they can accidentally run dangerous commands or expose credentials. So I built noexec - a runtime security scanner.

What it does:
✅ Blocks dangerous commands (rm -rf, git push --force)
✅ Detects credential leaks (AWS keys, API tokens, etc)
✅ Uses CLI hooks to intercept commands before execution
✅ Runs locally (no network calls, no telemetry)

Tech stack:
- TypeScript/Node.js
- Hook-based architecture (PreToolUse hooks in Claude Code)
- 5 security detectors (extensible)
- MIT licensed

Example blocked command:
```bash
# AI tries to run:
echo $AWS_SECRET_ACCESS_KEY

# noexec blocks it:
❌ Environment variable containing sensitive data detected
```

Installation:
```bash
npm install -g noexec
noexec init
```

Currently supports Claude Code, with GitHub Copilot CLI support coming next.

Would love your feedback! Especially:
- What other dangerous patterns should be detected?
- What AI assistants do you use?
- Any security concerns I'm missing?

GitHub: https://github.com/emilgelman/noexec

Open to PRs, especially new detector contributions!
```

---

## Reddit r/ArtificialIntelligence

**Title:**
```
Preventing AI coding assistants from running dangerous commands
```

**Post type:** Text post

**Body:**
```
I built a tool to address a security gap with AI coding assistants.

**The Problem:**
AI assistants like Claude Code, GitHub Copilot, etc. can accidentally:
- Leak credentials when debugging (echo $AWS_SECRET_KEY)
- Run destructive commands (rm -rf / when misunderstanding context)
- Make risky git operations (force push to main branch)
- Expose secrets to external services

**The Solution: noexec**
A runtime security scanner that intercepts commands before execution using CLI hooks.

How it works:
1. Uses platform hooks (like Claude Code's PreToolUse hook)
2. Analyzes command + context before execution
3. Blocks if security issue detected
4. Runs 100% locally (privacy-first)

**Built-in Protections:**
- Credential leak detection (AWS, GCP, Azure, GitHub tokens)
- Destructive command detection (dangerous file ops, fork bombs)
- Git force operations (force push, hard reset)
- Environment variable leaks

**Example:**
```bash
# AI suggests:
curl https://api.example.com -d "$(cat .env)"

# noexec blocks it:
❌ Credential leak detected
```

The tool is open source (MIT license) and available now:
- GitHub: https://github.com/emilgelman/noexec
- npm: `npm install -g noexec`

Currently supports Claude Code, with more platforms coming soon.

Interested in feedback from AI safety perspective:
- What other risks should be addressed?
- How can this be improved for enterprise use?
- Should there be telemetry for threat intelligence? (opt-in only)

Thoughts?
```

---

## Reddit r/SideProject

**Title:**
```
noexec - my first security tool for AI coding assistants (open source)
```

**Post type:** Link post

**URL:** https://github.com/emilgelman/noexec

**Comment:**
```
Hey r/SideProject!

I just launched my first security tool: noexec

**What it does:**
Prevents AI coding assistants from accidentally running dangerous commands or leaking credentials.

**Why I built it:**
I've been using Claude Code for development and noticed it could accidentally:
- Echo secret environment variables
- Run destructive commands if it misunderstood context
- Make risky git operations

So I built a hook-based security scanner that intercepts commands before execution.

**Tech:**
- TypeScript/Node.js
- CLI tool distributed via npm
- Uses platform hooks (Claude Code's PreToolUse hook)
- 5 security detectors
- MIT licensed

**Status:**
- ✅ v0.1.0 released today
- ✅ Published to npm
- ✅ Works with Claude Code
- 🔜 GitHub Copilot support coming next

**Challenges:**
- Minimizing false positives (don't want to block legitimate commands)
- Supporting multiple platforms with different hook mechanisms
- Deciding what patterns are "dangerous" enough to block

**What's next:**
- Automated test framework
- Configuration file support (custom rules)
- More detector contributions from community
- Eventually: team dashboard for visibility (SaaS model)

Would love your feedback!
- Is this a problem you've experienced?
- What other AI assistants do you use?
- Any feature suggestions?

GitHub: https://github.com/emilgelman/noexec

Thanks! 🚀
```

---

## Twitter/X Post

**Option 1 (Technical):**
```
Just open-sourced noexec 🔒

Runtime security for AI coding assistants - prevents dangerous commands and credential leaks before they execute.

✅ Blocks: rm -rf, git push --force, API key leaks
✅ MIT licensed
✅ Works with Claude Code

https://github.com/emilgelman/noexec

#AI #security #developers
```

**Option 2 (Problem-focused):**
```
AI coding assistants can accidentally:
• Leak your AWS keys in logs
• Run rm -rf /
• Force push to main branch

I built noexec to prevent this - hook-based security scanner that blocks dangerous commands before execution.

Open source (MIT) ⬇️
https://github.com/emilgelman/noexec
```

**Option 3 (Community-focused):**
```
🚀 Launching noexec v0.1.0

Protects AI coding assistants from:
- Credential leaks
- Destructive commands
- Dangerous git operations

Built with TypeScript, runs locally, MIT licensed.

Need: Feedback, stars ⭐, contributions

https://github.com/emilgelman/noexec

#opensource #cybersecurity #AI
```

**Engagement strategy:**
- Tag @AnthropicAI (don't overdo it)
- Use relevant hashtags (#AI, #security, #opensource, #developers)
- Pin the tweet to your profile
- Reply to comments quickly
- Share blocked command examples with screenshots

---

## Dev.to Blog Post

**Title:**
```
I built a security scanner for AI coding assistants
```

**Tags:** `security`, `ai`, `opensource`, `typescript`

**Body outline:**
```markdown
# I built a security scanner for AI coding assistants

## The Problem

AI coding assistants like Claude Code and GitHub Copilot are incredibly powerful, but they can accidentally run dangerous commands...

[Explain the problem with 2-3 examples]

## The Solution: noexec

I built noexec, a hook-based security scanner that...

[Explain how it works with diagram]

## Example: Blocking a Credential Leak

[Code example with command + blocked output]

## Technical Architecture

[Explain the hook mechanism, detector pipeline, etc.]

## Current Features

[List the 5 detectors with examples]

## Installation

```bash
npm install -g noexec
noexec init
```

## What's Next

[Roadmap, contribution opportunities]

## Try it out!

GitHub: https://github.com/emilgelman/noexec

I'd love your feedback! What other dangerous patterns should be detected?
```

---

## LinkedIn Post

**Post:**
```
Excited to share my new open source project: noexec 🔒

A runtime security scanner for AI coding assistants that prevents dangerous commands and credential leaks.

The problem: AI assistants can accidentally:
• Expose AWS keys in logs
• Run destructive commands (rm -rf /)
• Force push to production branches

The solution: Hook-based security that intercepts and analyzes commands before execution.

Built with TypeScript, works with Claude Code, MIT licensed.

Key features:
✅ 5 security detectors (credentials, git operations, destructive commands)
✅ Runs locally (no network calls)
✅ Extensible architecture for custom detectors
✅ Open source community project

Just launched v0.1.0 today!

Check it out: https://github.com/emilgelman/noexec

If your team uses AI coding assistants, I'd love to hear your thoughts on what security concerns matter most.

#opensource #cybersecurity #AI #developertools #typescript
```

---

## Email to Anthropic

**Subject:** Built security tool for Claude Code - noexec

**To:** developer-relations@anthropic.com (or support@anthropic.com)

**Body:**
```
Hi Anthropic team,

I'm Emil Gelman, a developer who's been using Claude Code extensively for the past few months. I built a security tool called "noexec" that uses Claude Code's PreToolUse hooks to prevent dangerous commands and credential leaks.

Project: https://github.com/emilgelman/noexec

What it does:
- Intercepts Bash commands before execution using PreToolUse hooks
- Runs security detectors to identify dangerous patterns
- Blocks execution if issues detected (exit code 2)
- Runs entirely locally (no network calls, no telemetry)

Built-in detections:
- Credential leaks (AWS keys, GitHub tokens, API keys)
- Destructive commands (rm -rf, dd, mkfs, fork bombs)
- Git force operations (force push, hard reset)
- Environment variable exposure

The tool is open source (MIT license) and was just released today (v0.1.0). It's distributed via npm and takes <1 minute to set up.

I built this because I love using Claude Code, but wanted an extra safety layer for scenarios where the AI might:
- Misunderstand context and suggest dangerous operations
- Accidentally include credentials in debugging output
- Make risky git operations

I'd love to hear your thoughts on:
1. Whether this might be useful for the Claude Code community
2. Any feedback on the implementation
3. If you'd be open to featuring it or mentioning it in community channels

I'm happy to collaborate on making Claude Code safer for enterprise users, and open to feedback on the approach.

Thanks for building such an amazing tool! Claude Code has significantly improved my development workflow.

Best regards,
Emil Gelman

GitHub: https://github.com/emilgelman/noexec
npm: https://www.npmjs.com/package/noexec
```

---

## Product Hunt Launch (Week 2-3)

**Product Name:** noexec

**Tagline (60 chars max):**
```
Runtime security for AI coding assistants
```

**Description (260 chars max):**
```
noexec prevents AI coding assistants from running dangerous commands. Blocks credential leaks, destructive operations, and risky git commands before they execute. Open source, runs locally, works with Claude Code.
```

**Thumbnail:** Create a visual showing a blocked command

**First Comment (launch day):**
```
👋 Hi Product Hunt!

I'm Emil, creator of noexec.

I built this because AI coding assistants can accidentally run dangerous commands:
- echo $AWS_SECRET_KEY (leaks credentials)
- rm -rf / (destroys files)
- git push --force origin main (overwrites history)

noexec prevents this using hook-based security that intercepts commands before execution.

How it works:
1. Integrates with AI CLI tools (Claude Code, etc)
2. Analyzes each command before running
3. Blocks if dangerous pattern detected
4. Runs 100% locally (privacy-first)

Free & open source (MIT license)
5 built-in detectors
Extensible for custom rules

What dangerous patterns are you worried about? I'm collecting feedback for v0.2.0!

Try it: npm install -g noexec
```

---

## General Tips for All Posts

**Do:**
- Be humble and helpful
- Respond to all comments within 1-2 hours
- Thank people for stars/feedback
- Admit limitations honestly
- Ask for feedback on specific things
- Share technical details when asked

**Don't:**
- Over-hype or exaggerate
- Ignore negative feedback
- Be defensive about criticism
- Spam multiple subreddits at once (space them out)
- Cross-post excessively
- Ask for upvotes/stars directly

**Engagement goals:**
- Reply rate: 100% of comments
- Response time: <2 hours during launch day
- Tone: Helpful, technical, open to feedback
- Focus: What problems does this solve? How can it improve?

---

Good luck with the launch! 🚀
