# Fast Revenue Path: Weeks 2-8

This document outlines the accelerated path to first revenue within 8 weeks of launch.

## Overview: Dual Revenue Model

**Strategy:** Offer both a SaaS dashboard AND custom detector services
- **Dashboard:** $99/month recurring (team analytics, policy management)
- **Custom Detectors:** $5k-10k one-time projects (company-specific rules)

**Goal:** Get first paying customer (either type) within 8 weeks

---

## Week 2-3: Build Minimal Cloud Platform (25-30 hours)

### Tech Stack Decision (Optimized for Speed)

**Frontend + Backend:**
- Next.js 14 (App Router) on Vercel
- Next.js API routes (no separate backend needed)
- Supabase for database + auth (free tier)
- LemonSqueezy for payments

**Why this stack:**
- Zero-config deployment (Vercel)
- Free tier good for 500+ users (Supabase)
- Built-in auth (Supabase)
- Handles tax compliance (LemonSqueezy)
- Total cost: $0-20/month for first 6 months

### Week 2 Tasks (10-12 hours)

**Database Schema Design (2 hours):**
```sql
-- Organizations table
CREATE TABLE organizations (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free', -- free, team, enterprise
  created_at TIMESTAMP DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  org_id UUID REFERENCES organizations(id),
  role TEXT NOT NULL DEFAULT 'member', -- admin, member
  created_at TIMESTAMP DEFAULT NOW()
);

-- API Keys table
CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id),
  key_hash TEXT NOT NULL,
  name TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP
);

-- Events table (blocked commands)
CREATE TABLE events (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id),
  timestamp TIMESTAMP DEFAULT NOW(),
  detector TEXT NOT NULL,
  command_hash TEXT NOT NULL, -- SHA256 of command (privacy)
  blocked BOOLEAN NOT NULL,
  severity TEXT NOT NULL,
  platform TEXT -- claude-code, copilot, etc
);
```

**Supabase Setup (2 hours):**
- Create Supabase project
- Create tables via SQL editor
- Set up Row Level Security (RLS) policies
- Configure authentication (email/password + GitHub OAuth)

**Next.js Project Setup (2 hours):**
```bash
npx create-next-app@latest noexec-cloud --typescript --tailwind --app
cd noexec-cloud
npm install @supabase/supabase-js @supabase/auth-helpers-nextjs
```

**API Routes (4 hours):**
- `POST /api/events` - Ingest from CLI
- `GET /api/events` - Query for dashboard
- `POST /api/api-keys` - Generate team keys
- `GET /api/stats` - Dashboard statistics

### Week 3 Tasks (8-10 hours)

**Frontend Pages (6 hours):**
- `/login` - Auth page
- `/dashboard` - Main analytics view
- `/api-keys` - Key management
- `/settings` - Team settings

**Dashboard Components (4 hours):**
- Timeline chart (blocked commands over time)
- Detector breakdown (which detectors triggered most)
- Platform usage (Claude Code vs Copilot vs others)
- Recent events table

### Week 4 Tasks (5-6 hours)

**Landing Page (2 hours):**
- Hero section with pricing tiers
- Feature comparison table
- Custom detectors CTA section
- FAQ

**Payment Integration (2 hours):**
- LemonSqueezy setup
- Webhook handler for subscription events
- Upgrade flow in dashboard

**Polish + Deploy (2 hours):**
- Error handling
- Loading states
- Deploy to Vercel
- Configure custom domain (optional)

---

## CLI Integration (2 hours)

**Update noexec analyze command:**

Add `--api-key` flag to optionally send events to cloud:

```typescript
// In src/commands/analyze.ts
interface AnalyzeOptions {
  hook: string;
  apiKey?: string; // NEW
}

// After detecting issues, optionally send to cloud
if (options.apiKey && detections.length > 0) {
  await sendToCloud(options.apiKey, toolUseData, detections);
}

async function sendToCloud(apiKey: string, toolData: any, detections: Detection[]) {
  try {
    const response = await fetch('https://noexec.app/api/events', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        detector: detections[0].detector,
        command_hash: hashCommand(JSON.stringify(toolData)),
        blocked: true,
        severity: detections[0].severity,
        platform: 'claude-code' // TODO: detect dynamically
      })
    });
  } catch (error) {
    // Fail silently - don't break CLI if cloud is down
  }
}

function hashCommand(cmd: string): string {
  // Simple hash for privacy (don't store actual commands)
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(cmd).digest('hex');
}
```

**Usage:**
```bash
# In ~/.claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "command": "noexec analyze --hook PreToolUse --api-key YOUR_TEAM_KEY",
        "matcher": "Bash"
      }
    ]
  }
}
```

---

## Pricing Page Structure

### Free Tier (CLI)
**$0/month**
- ✅ All security detectors
- ✅ Local command blocking
- ✅ Multi-platform support
- ✅ Open source
- ✅ Community support
- ❌ No team analytics
- ❌ No central policy management

**[Install via npm]** button → npm install instructions

### Team Tier
**$99/month**
- ✅ Everything in Free
- ✅ **Policy dashboard** (web-based analytics)
- ✅ Team-wide visibility
- ✅ 90-day event retention
- ✅ API key management
- ✅ Email support
- ✅ Unlimited team members

**[Start Free Trial]** button → Signup flow

### Enterprise Tier
**$499/month**
- ✅ Everything in Team
- ✅ **1 year event retention**
- ✅ **1 custom detector project included/year** ($5k value)
- ✅ SSO integration (coming soon)
- ✅ Priority support
- ✅ Dedicated Slack channel
- ✅ Compliance reports

**[Contact Sales]** button → Calendly link

---

## Custom Detector Services Section

**Prominent section on landing page:**

```
Need Company-Specific Security Rules?

We build custom detectors tailored to your organization:

✅ Internal API endpoints and URLs
✅ Proprietary credential patterns
✅ Cloud infrastructure commands (your specific AWS/GCP setup)
✅ Database operation policies (your schemas, your rules)
✅ Compliance-specific rules (HIPAA, SOC 2, PCI-DSS)

Starting at $5,000 per project
Typical delivery: 2-3 weeks
Includes: detector code, tests, documentation, integration support

[Schedule Consultation] → Calendly link (evenings/weekends only)
```

**Calendly Setup:**
- 30-minute consultation slots
- Only evenings/weekends (protect day job)
- Buffer time between calls
- Automated email with project questionnaire

---

## Week 5-6: Launch Cloud Platform

### Launch Sequence

**Soft Launch (Week 5):**
- Update GitHub README with cloud platform section
- Update npm package with `--api-key` support
- Post in HN: "Show HN: noexec cloud dashboard for team security"
- Email existing GitHub stargazers (if 100+):
  ```
  Subject: New: noexec team dashboard

  Hi [name],

  You starred noexec on GitHub - thank you!

  We've launched a team dashboard ($99/month) with:
  - Team-wide analytics
  - Policy management
  - 90-day event retention

  Free for first 50 teams (limited beta).

  Try it: https://noexec.app

  Best,
  Emil
  ```

**Product Hunt Launch (Week 6):**
- Prepare PH listing
- Create demo video (3 minutes max)
- Get hunter to submit (or submit yourself)
- Launch at 12:01am PT
- Engage all day
- Offer PH-exclusive discount: "First 10 teams get 50% off for 6 months"

### Conversion Strategy

**Free → Paid Triggers:**
1. After 10 blocked commands, show banner: "Upgrade to see full analytics"
2. Email after 30 days: "Your team blocked 47 dangerous commands - see what they were"
3. When team has 3+ users: "Your team is growing - try Team plan free for 14 days"

**Custom Detector Lead Gen:**
1. On dashboard: "Need custom rules? [Contact us]"
2. After blocking uncommon patterns: "Want to whitelist this? Enterprise plan includes custom detectors"
3. Email high-usage teams: "Noticed you blocked 200+ commands - we can help optimize your rules"

---

## Week 7-8: Sales Outreach (Safe Methods)

### NO Cold Outreach (Job-Safe)

**Instead, use inbound methods:**

1. **Content Marketing:**
   - Blog post: "5 Ways AI Assistants Can Accidentally Leak Credentials"
   - Post to HN, Reddit, dev.to
   - Include CTA at end: "Prevent this with noexec"

2. **Community Engagement:**
   - Answer questions on HN/Reddit about AI coding security
   - Mention noexec naturally in context
   - Don't spam, add value first

3. **Ask HN Post (Week 7):**
   ```
   Ask HN: How do you handle security with AI coding assistants at work?

   Our company is exploring Claude Code/Copilot for developers, but
   security team is concerned about:
   - Credential leaks
   - Destructive commands
   - Compliance

   What approaches have worked for you?
   ```
   - Engage with responses
   - DM people who express interest: "I built noexec, would love your feedback"
   - Offer free consultation calls

4. **Show Your Work:**
   - Weekly updates on progress (Twitter, blog)
   - Share metrics transparently
   - Build in public community engagement

### Consultation Calls (Evenings/Weekends)

**Structure:**
- 30 minutes
- Understand their use case
- Offer both dashboard AND custom detector options
- No pressure, just listening
- Follow up with email proposal

**Proposal Template (Custom Detectors):**
```
Subject: Custom Detector Project Proposal for [Company]

Hi [Name],

Great talking with you about [Company]'s security needs for AI assistants.

Based on our call, I propose building custom detectors for:
1. [Specific need 1]
2. [Specific need 2]
3. [Specific need 3]

Project scope:
- 3 custom detectors
- Full test coverage
- Documentation
- Integration support
- 2-week delivery

Investment: $5,000

This includes unlimited revisions during development and 30 days of
post-delivery support.

Want to proceed? I can start next week.

Best,
Emil
```

---

## Success Metrics: Week 8 Targets

### Dashboard Sales
**Target: 1-2 paying teams**
- 1 team @ $99/month = $1,188/year
- 2 teams @ $99/month = $2,376/year

**Conversion funnel:**
- 1,000 npm downloads/week
- 50 dashboard signups (5% conversion)
- 5 trial starts (10% conversion from signups)
- 1-2 paid conversions (20-40% trial → paid)

### Custom Detector Sales
**Target: 1 project closed**
- 1 project @ $5,000 = immediate revenue
- Plus: potential ongoing dashboard customer

**Lead funnel:**
- 10 consultation requests
- 5 qualified leads (right company size/budget)
- 2-3 proposals sent
- 1 project closed (33-50% close rate)

### Combined Target
**Total Week 8 Revenue:**
- 2 teams @ $99/month = $2,376/year recurring
- 1 custom project = $5,000 one-time
- **Total Year 1 Revenue: $7,376** from 3 customers

---

## Decision Point: Month 3

**After 2-3 months, you'll have clear data:**

### Scenario 1: Dashboard is Selling (2+ teams)
**Action:**
- ✅ Double down on SaaS platform
- ✅ Add more features (SSO, integrations)
- ✅ Focus on growing MRR
- ✅ Consider hiring part-time help
- ⏳ Keep custom detectors as upsell

**Indicators:**
- Strong trial → paid conversion (>20%)
- Low churn
- Feature requests from paying customers
- Word-of-mouth growth

### Scenario 2: Custom Projects are Selling (1-2 closed)
**Action:**
- ✅ Position as consulting/services
- ✅ Raise prices to $10k-15k
- ✅ Build detector library as portfolio
- ✅ Eventually productize common patterns
- ⏳ Dashboard becomes lead gen tool

**Indicators:**
- Multiple consultation requests
- Enterprises willing to pay
- Repeat customers
- Referrals

### Scenario 3: Both are Working
**Action:**
- ✅ Keep doing both (synergistic)
- ✅ Custom projects fund platform development
- ✅ Platform generates recurring revenue
- ✅ Consider hiring contractor for custom work
- 🎯 This is the ideal scenario

**Indicators:**
- Dashboard: 2-5 paying teams
- Services: 1-2 projects/quarter
- Total: $10k+ quarterly revenue

### Scenario 4: Neither is Selling (<1 customer)
**Action:**
- 🔄 Pivot to pure open source + sponsorships
- 🔄 Try GitHub Sponsors, Open Collective
- 🔄 Focus on community growth
- 🔄 Revisit monetization in 6 months
- 💡 Consider different positioning

**Indicators:**
- High GitHub stars but no conversions
- Dashboard signups but no trials
- Consultation requests but no closes
- Need to validate problem/solution fit

---

## Infrastructure Costs Summary

### Months 1-6 (Bootstrap Phase)
- **Vercel:** $0 (free tier)
- **Supabase:** $0 (free tier, 500MB database)
- **LemonSqueezy:** $0 base (5% + $0.50 per transaction)
- **Domain:** $15/year (noexec.app)
- **Calendly:** $0 (free tier)
- **Total:** ~$15 for 6 months

### Months 7-12 (If growing)
- **Vercel Pro:** $20/month (if needed)
- **Supabase Pro:** $25/month (if >500 users)
- **Other services:** $10/month
- **Total:** $55/month ($330/6 months)

**Revenue Break-even:** 1 dashboard customer covers all costs

---

## Risk Mitigation

### Job Safety
- ✅ All work evenings/weekends
- ✅ No cold outreach during work hours
- ✅ Use personal email for everything
- ✅ Calendly only shows evening/weekend slots
- ✅ No LinkedIn posts during work day

### Time Management
- ✅ MVP takes ~30 hours (doable in 3 weeks)
- ✅ Launch activities on weekends
- ✅ Automated tools reduce ongoing time
- ✅ Can pause if needed

### Financial Risk
- ✅ <$100 total investment for 6 months
- ✅ No employees/contractors needed
- ✅ Can shut down anytime if not working
- ✅ Skills gained have career value

---

## Final Thoughts

**This plan is aggressive but achievable because:**
1. You have a working product (noexec CLI)
2. You have initial traction potential (open source)
3. You're offering two revenue paths (more shots on goal)
4. The tech stack is optimized for speed
5. The investment is minimal

**Key to success:**
- Ship fast, iterate faster
- Talk to users constantly
- Don't build features no one asked for
- Focus on getting first customer ASAP
- Use their feedback to guide development

**Remember:**
- First customer is the hardest
- Second customer validates it's not a fluke
- Third customer = you have a pattern
- At that point, you can scale

You've got this! 🚀

---

## Next Session Goals

When you continue working on this:

1. Complete GitHub + npm launch (Week 1)
2. Monitor initial traction
3. If 100+ stars, proceed with cloud platform
4. If <50 stars, focus on content marketing first
5. Stay flexible, let data guide decisions

Good luck! 🎉
