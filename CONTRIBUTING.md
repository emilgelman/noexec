# Contributing to noexec

Thank you for your interest in contributing to noexec! We welcome contributions from the community.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Provide clear steps to reproduce bugs
- Include your platform and noexec version

### Contributing Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Add tests for your changes
5. Run the test suite (`npm test`)
6. Commit with clear messages (`git commit -m "Add feature: ..."`)
7. Push to your fork (`git push origin feature/my-feature`)
8. Open a Pull Request

### Contributing Detectors

New detectors are especially welcome! To add a detector:

1. Create a new file in `src/detectors/` (e.g., `my-detector.ts`)
2. Export an async function matching the `Detector` type:

   ```typescript
   import { Detection } from './index';

   export async function detectMyIssue(toolUseData: any): Promise<Detection | null> {
     const toolInput = JSON.stringify(toolUseData);

     if (/* detection logic */) {
       return {
         severity: 'high', // or 'medium', 'low'
         message: 'Description of the security issue',
         detector: 'my-detector-name'
       };
     }

     return null;
   }
   ```

3. Add your detector to `src/commands/analyze.ts` in the `detectors` array
4. Write tests in `src/detectors/__tests__/my-detector.test.ts`
5. Document what your detector catches in your PR description
6. Rebuild with `npm run build` and test with `./test-example.sh`

### Code Style

- Use TypeScript
- Follow existing code formatting
- Add comments for complex logic
- Keep functions focused and testable

### Testing

- All new features need tests
- Run `npm test` before submitting PRs
- Aim for high test coverage

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/noexec.git
cd noexec

# Install dependencies
npm install

# Build the project
npm run build

# Link for local testing
npm link

# Run tests
npm test

# Watch mode for development
npm run dev
```

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming community

## Questions?

Open a GitHub Discussion or Issue - we're happy to help!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
