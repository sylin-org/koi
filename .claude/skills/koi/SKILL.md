```markdown
# koi Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `koi` TypeScript codebase. It covers file organization, code style, commit standards, and testing approaches to help contributors write consistent, high-quality code.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `myComponent.ts`, `userService.test.ts`

### Imports
- Use **relative imports** for referencing other modules within the project.
  - Example:
    ```typescript
    import { helperFunction } from './utils';
    ```

### Exports
- Use **named exports** instead of default exports.
  - Example:
    ```typescript
    // Good
    export function fetchData() { ... }

    // Avoid
    // export default function fetchData() { ... }
    ```

### Commit Messages
- Follow **conventional commit** standards.
- Common prefixes: `ci`, `fix`
- Keep commit messages concise (average 80 characters).
  - Example:
    ```
    fix: resolve issue with user authentication flow
    ci: update build pipeline for Node 18
    ```

## Workflows

### Commit Code
**Trigger:** When you have made changes and are ready to commit.
**Command:** `/commit`

1. Stage your changes:
    ```
    git add .
    ```
2. Write a conventional commit message:
    ```
    git commit -m "fix: correct typo in login logic"
    ```
3. Push your changes:
    ```
    git push
    ```

### Run Tests
**Trigger:** Before pushing code or opening a pull request.
**Command:** `/test`

1. Locate test files (pattern: `*.test.*`).
2. Run the project's test runner (framework unknown; try common tools):
    ```
    # Example for Jest
    npx jest
    ```
3. Review output and fix any failing tests.

## Testing Patterns

- Test files follow the pattern: `*.test.*` (e.g., `userService.test.ts`).
- The testing framework is not specified; check for scripts or dependencies in `package.json`.
- Place tests alongside implementation files or in a dedicated `tests` directory.
- Example test file:
    ```typescript
    // userService.test.ts
    import { getUser } from './userService';

    test('should return user data', () => {
      const user = getUser('123');
      expect(user.id).toBe('123');
    });
    ```

## Commands
| Command   | Purpose                                   |
|-----------|-------------------------------------------|
| /commit   | Guide for making a conventional commit    |
| /test     | Steps to run and verify tests             |
```
