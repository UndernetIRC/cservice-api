# Contributing to Channel Services API

We welcome contributions to the Channel Services API! This document provides guidelines for contributing to the project.

## Table of Contents

- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Reporting Issues](#reporting-issues)
- [Code of Conduct](#code-of-conduct)

## Development Workflow

### 1. Fork and Clone

Fork the repository on GitHub and clone your fork locally:

```bash
git clone https://github.com/your-username/cservice-api.git
cd cservice-api
```

### 2. Create a Feature Branch

Create a branch for your changes:

```bash
git checkout -b feature/your-feature-name
```

### 3. Set Up Development Environment

Install dependencies and start development services:

```bash
# Install dependencies
go mod download

# Start development services
docker-compose up -d
```

For detailed development setup instructions, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

### 4. Make Your Changes

Follow our coding standards (see below) when making changes.

### 5. Run Tests and Linting

Ensure all tests pass and code meets quality standards:

```bash
make test
make integration-test
make lint
```

### 6. Commit Your Changes

Write clear, concise commit messages following conventional commits format:

```bash
git add .
git commit -m "feat: add new feature description"
```

**Commit message format:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

### 7. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 8. Create a Pull Request

Open a pull request on GitHub with a clear description of your changes.

## Coding Standards

### Code Style

- **Follow Go conventions**: Use `gofmt` and `golint`
- **Meaningful names**: Use clear, descriptive variable and function names
- **Comments**: Write godoc comments for exported functions and types
- **Keep functions small**: Each function should do one thing well

### Testing Requirements

- **Unit tests**: All new code must have unit tests
- **Integration tests**: Add integration tests for new API endpoints
- **Coverage**: Maintain or improve test coverage (aim for >90%)
- **Table-driven tests**: Use table-driven tests for multiple scenarios

Example:

```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"case 1", "input1", "output1"},
        {"case 2", "input2", "output2"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := YourFunction(tt.input)
            if result != tt.expected {
                t.Errorf("got %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Database Changes

- **Never modify existing migrations**: Always create new migration files
- **Use migrations**: `migrate create -ext sql -dir db/migrations <name>`
- **Update sqlc**: Run `make generate-sqlc` after schema changes
- **Update mocks**: Run `make generate-mocks` after interface changes
- **Test migrations**: Test both up and down migrations

### Documentation

- **Update API docs**: Document new endpoints in code comments and run `make docs`
- **Update README**: Add new features to README.md when appropriate
- **Add examples**: Include usage examples in pull request description
- **Code comments**: Document exported functions, types, and complex logic

### Security

- **Input validation**: Validate all user input
- **SQL injection**: Use parameterized queries (sqlc handles this)
- **Authentication**: Ensure proper JWT validation for protected endpoints
- **Sensitive data**: Never log passwords, tokens, or sensitive information

## Pull Request Guidelines

### PR Description Template

Use this template for your pull request description:

```markdown
## Description
Brief description of the changes and why they were made.

## Changes Made
- List of specific changes
- New features or bug fixes
- Breaking changes (if any)

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] All tests passing

## Documentation
- [ ] Code comments updated
- [ ] API documentation updated
- [ ] README updated (if needed)

## Screenshots/Examples
(If applicable, add screenshots or code examples)
```

### Review Process

1. **Automated checks**: CI tests, linting, and security checks must pass
2. **Code review**: Maintainers will review your code
3. **Testing**: Manual testing may be performed for significant changes
4. **Approval**: Once approved, maintainers will merge your PR

### PR Best Practices

- **Keep PRs focused**: One feature or fix per PR
- **Small commits**: Make small, logical commits
- **Rebase**: Rebase on main before submitting to avoid conflicts
- **Respond to feedback**: Address review comments promptly
- **Update tests**: Ensure tests reflect your changes

## Reporting Issues

### Before Reporting

1. **Search existing issues** to avoid duplicates
2. **Check documentation** for solutions
3. **Test with latest version** to ensure the issue still exists

### Creating an Issue

When reporting bugs or requesting features, provide:

#### For Bug Reports:
- **Go version**: Output of `go version`
- **Operating system**: Linux, macOS, Windows, etc.
- **Steps to reproduce**: Clear, numbered steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Error messages**: Complete error output or logs
- **Configuration**: Relevant configuration settings

#### For Feature Requests:
- **Use case**: Why is this feature needed?
- **Description**: What should the feature do?
- **Alternatives**: What alternatives have you considered?
- **Backward compatibility**: Any breaking changes?

### Issue Labels

Issues are tagged with labels to help organize and prioritize:

- `bug` - Something isn't working
- `enhancement` - New feature or improvement
- `documentation` - Documentation improvements
- `help wanted` - Extra attention needed

## Feature Requests

### Proposing New Features

1. **Create an issue** to discuss the feature first
2. **Provide use cases** explaining why it's needed
3. **Consider impact** on existing features and backward compatibility
4. **Offer to implement** if you're willing to contribute the code

### Feature Discussion

- Be open to feedback and alternative solutions
- Consider maintainability and long-term support
- Think about performance implications
- Ensure it aligns with project goals

## Getting Help

- **Questions**: Open a GitHub issue with the "question" label
- **Chat**: Join our IRC channel #coder-com on Undernet
- **Documentation**: Check [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development guides

## Code of Conduct

### Our Standards

- **Be respectful**: Treat everyone with respect and kindness
- **Be constructive**: Provide helpful feedback and suggestions
- **Be collaborative**: Work together toward common goals
- **Be professional**: Keep discussions focused and on-topic

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Trolling, insulting, or derogatory remarks
- Publishing others' private information
- Any conduct that could be considered inappropriate in a professional setting

### Enforcement

Project maintainers have the right to remove comments, commits, code, issues, and other contributions that do not align 
with this Code of Conduct. Unacceptable behavior may result in temporary or permanent bans from the project.

### Reporting

Report unacceptable behavior to project maintainers via GitHub or email. All reports will be reviewed and investigated
promptly and fairly.

---

We follow the [Go Community Code of Conduct](https://golang.org/conduct).

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Channel Services API! 🎉
