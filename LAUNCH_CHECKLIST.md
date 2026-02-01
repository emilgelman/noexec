# Launch Checklist for noexec v0.1.0

Use this checklist to launch noexec to the public.

## Pre-Launch Preparation

### GitHub Setup
- [ ] Create GitHub repository at `github.com/emilgelman/noexec`
  - Name: `noexec`
  - Description: `Runtime security for AI coding assistants - prevent dangerous commands and credential leaks`
  - Public repository
  - Do NOT initialize with README (we have one)

- [ ] Push code to GitHub:
  ```bash
  git remote add origin https://github.com/emilgelman/noexec.git
  git branch -M main
  git push -u origin main
  ```

- [ ] Configure repository settings:
  - [ ] Add topics: `security`, `ai`, `claude-code`, `github-copilot`, `ai-safety`, `developer-tools`
  - [ ] Enable Issues
  - [ ] Enable Discussions (optional but recommended)
  - [ ] Add repository description
  - [ ] Set website URL (can add later when you have one)

- [ ] Create v0.1.0 release:
  - [ ] Go to Releases → Draft a new release
  - [ ] Tag: `v0.1.0`
  - [ ] Title: `noexec v0.1.0 - Initial Release`
  - [ ] Description: Copy from CHANGELOG.md
  - [ ] Mark as latest release
  - [ ] Publish

### npm Setup
- [ ] Verify npm account is set up
- [ ] Login to npm:
  ```bash
  npm login
  ```

- [ ] Verify package builds correctly:
  ```bash
  npm run build
  ./test-simple.sh
  ```

- [ ] Publish to npm:
  ```bash
  npm publish --access public
  ```

- [ ] Verify publication: Visit https://npmjs.com/package/noexec

## Launch Day (Allow 3-4 hours for monitoring)

### Timing
**Best time to launch:** Weekday morning, 9-11am Pacific Time (12-2pm Eastern)
- HackerNews peaks during US working hours
- You need to be available to respond to comments for 2-4 hours after posting

### Platform Posts

#### 1. HackerNews (MOST IMPORTANT)
- [ ] Go to https://news.ycombinator.com/submit
- [ ] Post type: Link
- [ ] Title: `Show HN: noexec – Runtime security for AI coding assistants`
  - Keep title under 80 characters
  - Use "–" (em dash) not "-"
  - Don't over-hype
- [ ] URL: `https://github.com/emilgelman/noexec`
- [ ] Submit
- [ ] **CRITICAL:** Monitor comments for first 2-4 hours
- [ ] Reply thoughtfully to ALL comments (positive and negative)
- [ ] If someone reports a bug, acknowledge and thank them

**HN Tips:**
- Be humble, not salesy
- Focus on technical details in comments
- If asked "why not X?", explain thoughtfully
- Upvote good questions/feedback
- Don't argue, learn from criticism

#### 2. Reddit Posts

**r/programming** (400k+ members)
- [ ] Post type: Link post
- [ ] Title: `I built a security scanner for AI coding assistants`
- [ ] URL: GitHub repo
- [ ] Flair: Pick most relevant (if required)
- [ ] Comment on your own post with context (why you built it, what it does)

**r/ArtificialIntelligence** (200k+ members)
- [ ] Post type: Text or Link
- [ ] Title: `Preventing AI coding assistants from running dangerous commands`
- [ ] Body: Brief explanation + link to GitHub
- [ ] Focus on AI safety angle

**r/SideProject** (300k+ members)
- [ ] Post type: Link
- [ ] Title: `noexec - my first security tool for AI coding assistants (open source)`
- [ ] URL: GitHub repo
- [ ] Engage with feedback

**r/devops** (optional, 200k+ members)
- [ ] Post type: Link
- [ ] Title: `Tool for preventing dangerous commands in AI coding assistants`
- [ ] URL: GitHub repo

#### 3. Twitter/X (if you have account)
- [ ] Tweet template:
  ```
  Just open-sourced noexec 🔒

  Runtime security for AI coding assistants - prevents dangerous commands and credential leaks before they execute.

  ✅ Blocks: rm -rf, git push --force, API key leaks
  ✅ MIT licensed
  ✅ Works with Claude Code

  https://github.com/emilgelman/noexec

  #AI #security #developers
  ```
- [ ] Tag relevant accounts: @AnthropicAI, @github (don't overdo it)
- [ ] Pin the tweet to your profile

#### 4. Dev.to (optional, great for SEO)
- [ ] Write a quick post:
  - Title: "I built a security scanner for AI coding assistants"
  - Tags: `security`, `ai`, `opensource`, `javascript`
  - Body: Explain the problem, show examples, link to GitHub
  - Include code snippets of blocked commands
- [ ] Post URL to Reddit/Twitter

#### 5. LinkedIn (if you want professional visibility)
- [ ] Post update:
  ```
  Excited to share my new open source project: noexec

  A runtime security scanner for AI coding assistants that prevents dangerous commands and credential leaks.

  Built with TypeScript, works with Claude Code, MIT licensed.

  [Link to GitHub]

  #opensource #cybersecurity #AI #developer tools
  ```

### Email Outreach

#### Anthropic (Claude Code team)
- [ ] Subject: `Built security tool for Claude Code - noexec`
- [ ] Body template:
  ```
  Hi [Name/Team],

  I'm Emil, a developer who's been using Claude Code extensively. I built a security tool called "noexec" that uses Claude Code's PreToolUse hooks to prevent dangerous commands and credential leaks.

  GitHub: https://github.com/emilgelman/noexec

  Key features:
  - Blocks destructive commands (rm -rf, git push --force, etc)
  - Detects credential leaks (AWS keys, API tokens, etc)
  - Open source (MIT license)
  - Works out-of-box with Claude Code

  I'd love to hear your thoughts, and if you think it's useful for the Claude Code community, I'd appreciate any visibility you could provide.

  Best,
  Emil Gelman
  ```
- [ ] Send to: developer-relations@anthropic.com or support@anthropic.com
- [ ] Also post in Claude Code Discord/forum if there is one

## Post-Launch (First 48 hours)

### Monitoring
- [ ] Check HackerNews post ranking every 30 minutes (first 4 hours)
- [ ] Respond to ALL comments on HN within 1 hour
- [ ] Monitor Reddit comments and replies
- [ ] Check GitHub for stars/issues/PRs
- [ ] Monitor npm download stats: https://npm-stat.com/charts.html?package=noexec

### Engagement
- [ ] Thank everyone who stars the repo (optional but nice)
- [ ] Respond to GitHub issues within 24 hours
- [ ] If someone finds a bug, prioritize fixing it
- [ ] If someone requests a feature, add it to issues/roadmap
- [ ] Share positive feedback on social media (with permission)

### Analytics Tracking
Create a simple spreadsheet to track:
- [ ] GitHub stars (daily)
- [ ] npm downloads (weekly)
- [ ] GitHub issues opened
- [ ] Community contributions
- [ ] Traffic sources (if you set up analytics)

## Week 1 Post-Launch Tasks

- [ ] Write a "Launch Day" recap post (what worked, what didn't)
- [ ] Start working on Week 2-3 priorities (test framework, more detectors)
- [ ] Engage with any community PRs or issues
- [ ] Consider creating a demo video/GIF
- [ ] Plan next blog post or announcement

## Success Metrics (End of Week 1)

**Minimum Success:**
- [ ] 50+ GitHub stars
- [ ] 500+ npm downloads
- [ ] 3+ issues/discussions opened by community
- [ ] Code is published and working

**Good Success:**
- [ ] 100+ GitHub stars
- [ ] 1,000+ npm downloads
- [ ] 5+ community contributions
- [ ] Positive reception on HN (30+ points)

**Great Success:**
- [ ] 200+ GitHub stars
- [ ] 2,000+ npm downloads
- [ ] 10+ community contributions
- [ ] HN front page (100+ points)
- [ ] Featured in newsletter or blog

## Emergency Contacts

If something goes wrong:

**npm publication issues:**
- https://docs.npmjs.com/cli/v10/commands/npm-publish
- npm support: https://npmjs.com/support

**GitHub issues:**
- https://support.github.com

**HackerNews moderation:**
- Email: hn@ycombinator.com (if your post is flagged/killed)

## Final Pre-Launch Check

Before you hit "publish":

- [ ] README looks good on GitHub (check rendering)
- [ ] Package builds without errors (`npm run build`)
- [ ] Tests pass (`./test-simple.sh`)
- [ ] package.json has correct repository URL
- [ ] LICENSE file is present
- [ ] All links in README work
- [ ] You have 3-4 hours available to monitor launch
- [ ] It's a weekday during US business hours (optional but recommended)

---

## You're Ready! 🚀

When you're ready, start with GitHub + npm, then do the community posts.

**Remember:**
- Be humble and open to feedback
- Thank everyone who engages
- Don't be defensive about criticism
- Learn from every comment
- Celebrate the milestone!

Good luck! You've built something valuable. Now let the world know about it.
