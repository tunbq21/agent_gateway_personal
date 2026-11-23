# Test Check (Shared Tests)

Thư mục này chứa các file test dùng chung cho dự án (được theo dõi và đẩy lên Git).

- `unit_test/`: Chứa các file unit test cục bộ (nội dung bên trong được gitignore).
- `integration_test/`: Chứa các file integration test cục bộ (nội dung bên trong được gitignore).
- `test_check/`: Chứa các kịch bản kiểm tra dùng chung (health, cấu hình CEL, quy tắc phân quyền MCP).

## Cách chạy nhanh

```bash
python -m unittest discover -s test/test_check -p "test_*.py" -v
```
