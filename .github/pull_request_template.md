## Description
<!-- Provide a brief description of the changes in this PR -->

## Type of Change
<!-- Mark the relevant option with an "x" -->
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Code refactoring (no functional changes, no api changes)
- [ ] ⚡ Performance improvements
- [ ] 🔒 Security improvement
- [ ] 🧪 Test improvements
- [ ] 🔨 Build/CI improvements
- [ ] 🎨 Style/formatting changes

## Related Issues
<!-- Link any related issues here -->
Fixes #(issue number)
Related to #(issue number)

## Changes Made
<!-- Describe the changes in detail -->
- 
- 
- 

## Testing
<!-- Describe the tests you've run and any testing instructions -->
- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Tested manually with the following scenarios:
  - [ ] Basic certificate validation
  - [ ] Custom validators (if applicable)
  - [ ] Error handling
  - [ ] Protocol detection (if applicable)

### Test Commands Run
```bash
# Add the commands you used to test this change
pytest tests/
python -m ruff check .
python -m ruff format --check .
```

## Checklist
<!-- Mark completed items with an "x" -->
- [ ] My code follows the project's coding standards
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings or errors
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Security Considerations
<!-- If this PR has security implications, describe them -->
- [ ] This change does not introduce security vulnerabilities
- [ ] I have considered the security implications of this change
- [ ] Security review is not needed / Security review has been completed

## Documentation
<!-- Mark what documentation has been updated -->
- [ ] Code comments updated
- [ ] README.md updated (if needed)
- [ ] API documentation updated (if needed)
- [ ] Usage examples updated (if needed)
- [ ] Changelog updated (if applicable)

## Breaking Changes
<!-- If this PR introduces breaking changes, describe them -->
None

<!-- OR describe breaking changes: -->
<!-- 
This PR introduces the following breaking changes:
- Changed API method signatures
- Removed deprecated functionality
- Modified return types
-->

## Screenshots (if applicable)
<!-- Add screenshots to help explain your changes -->

## Additional Notes
<!-- Add any additional notes for reviewers -->

---

### For Maintainers
- [ ] Version bump needed
- [ ] Release notes updated
- [ ] Migration guide needed (for breaking changes)
