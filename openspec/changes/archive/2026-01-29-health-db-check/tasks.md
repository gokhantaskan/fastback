# Tasks: Health Database Check

## 1. Update health router

- [x] 1.1 Add SessionDep import and database check logic to health endpoint
- [x] 1.2 Return 503 with unhealthy status when database check fails

## 2. Update tests

- [x] 2.1 Update existing health test for new response format
- [x] 2.2 Add test for database failure scenario (mock session to raise exception)
