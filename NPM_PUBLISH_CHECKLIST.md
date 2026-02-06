# npm Publish Checklist

Use this checklist before publishing to npm.

## Pre-Publish Checklist

### 1. Code Quality

- [ ] All tests passing (`npm test`)
- [ ] Linting passes (`npm run lint`)
- [ ] No TypeScript errors (`npm run build`)
- [ ] Code coverage acceptable (`npm run test:coverage`)

### 2. Version and Metadata

- [ ] Version bumped in `package.json`
- [ ] Version updated in `src/cli.ts`
- [ ] CHANGELOG.md updated with release notes
- [ ] All changes committed to git
- [ ] Git tag created for version (e.g., `v1.0.0`)

### 3. Documentation

- [ ] README.md is up to date
- [ ] CHANGELOG.md reflects all changes
- [ ] All documentation files reviewed
- [ ] Examples work correctly

### 4. Package Contents

- [ ] Build artifacts generated (`npm run build`)
- [ ] Check package contents (`npm pack` and inspect .tgz)
- [ ] Verify `files` field in package.json includes all necessary files
- [ ] LICENSE file present
- [ ] README.md present

### 5. Testing the Package

- [ ] Test local install: `npm pack && npm install -g ./noexec-1.0.0.tgz`
- [ ] Verify CLI works: `noexec --version`
- [ ] Test init command: `noexec init`
- [ ] Test analyze with sample input
- [ ] Uninstall test package: `npm uninstall -g noexec`

### 6. npm Registry

- [ ] Logged into npm (`npm whoami`)
- [ ] Have 2FA ready if enabled
- [ ] Check if package name is available (first publish only)
- [ ] Review npm package page after publish

### 7. Post-Publish

- [ ] Verify package appears on npm: https://www.npmjs.com/package/noexec
- [ ] Test install from npm: `npm install -g noexec`
- [ ] Push git tags: `git push origin v1.0.0`
- [ ] Create GitHub release with release notes
- [ ] Announce release (optional: Twitter, Discord, etc.)

## Commands

```bash
# 1. Final checks
npm test
npm run lint
npm run build

# 2. Test package locally
npm pack
npm install -g ./noexec-1.0.0.tgz
noexec --version
noexec init --help
npm uninstall -g noexec

# 3. Publish to npm
npm publish

# 4. Create git tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# 5. Verify
npm info noexec
npm install -g noexec
```

## Emergency Unpublish

If you need to unpublish within 72 hours:

```bash
npm unpublish noexec@1.0.0
```

**Warning**: Unpublishing is discouraged. Use `npm deprecate` instead for later versions:

```bash
npm deprecate noexec@1.0.0 "This version has a critical bug, please upgrade to 1.0.1"
```

## Troubleshooting

### Package Name Already Taken

- Choose a different name or scope it: `@yourusername/noexec`

### 2FA Issues

- Ensure you have your authenticator app ready
- Use `npm login` to refresh session if needed

### Build Issues

- Clear dist: `rm -rf dist`
- Rebuild: `npm run build`
- Check TypeScript errors

### Missing Files in Package

- Review `files` field in package.json
- Use `npm pack` to inspect contents before publishing
- Add any missing patterns to `files` array
