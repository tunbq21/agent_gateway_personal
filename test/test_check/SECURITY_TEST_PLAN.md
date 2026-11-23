# Kế Hoạch Kiểm Thử Bảo Mật Toàn Diện 3 Môi Trường (Dev → UAT → Production)

Tài liệu đặc tả chiến lược và bộ **60 Test Cases kiểm thử bảo mật chuẩn doanh nghiệp** cho nền tảng **AI & MCP Gateway**, phân tách theo đúng 3 môi trường và 3 thư mục kiểm thử:

| Môi trường | Thư mục chứa Test | Số lượng | Theo dõi Git | Mục tiêu & Phạm vi |
| :--- | :--- | :---: | :--- | :--- |
| **Production & CI** | `test/test_check/` | **14 TCs** | **Tracked** *(Đẩy lên Git dùng chung)* | Kiểm tra Hardening cấu hình `config.enterprise.yaml` (`jwtAuth`, `oidc`, không lộ key tĩnh, CORS, `localRateLimit`) và smoke-check CEL không xâm lấn. |
| **DEV** | `test/unit_test/` | **34 TCs** | **Gitignore** *(Không đẩy lên Git)* | Kiểm thử hộp trắng (White-box) xác thực chữ ký JWT HS256, chặn `alg:none`/hết hạn, logic CEL, tấn công IDOR, ép kiểu tham số, Prompt/SQL Injection (kể cả viết HOA/thường) và RBAC/ABAC. |
| **UAT / Staging** | `test/integration_test/` | **12 TCs** | **Gitignore** *(Không đẩy lên Git)* | Kiểm thử tích hợp End-to-End qua HTTP/MCP (`:3000/mcp` & `:15000`), kiểm tra chặn `403`, chặn JSON-RPC Batch `400`, chặn `429` Rate Limit và đối chiếu Audit Log / Analytics. |
| **TỔNG CỘNG** | **Toàn dự án** | **60 TCs** | — | **Phủ kín 5 lớp bảo mật: Config Hardening, JWT Signature AuthN, Anti-IDOR, Injection/RateLimit, Audit & Logging.** |

---

## 1. Chiến lược kiểm thử theo từng môi trường

1. **Môi trường DEV (`test/unit_test/test_security_dev.py` — 34 TCs):**
   - Chạy offline hoàn toàn (< 10ms), không phụ thuộc mạng hay database.
   - Kiểm tra chặt xác thực chữ ký HMAC-SHA256, thời hạn `exp`, và cơ chế **Fail-Closed** với mọi đầu vào dị dạng.
2. **Môi trường UAT / Staging (`test/integration_test/test_security_uat.py` — 12 TCs):**
   - Bắn request HTTP/JSON-RPC thật vào Gateway (`:3000/mcp`) với token JWT đã ký số HS256 và phiên `Mcp-Session-Id` thật.
   - Xác minh Gateway chặn ngay từ tầng Proxy (`400` cho Batch/Parse error, `403` cho vi phạm CEL, `429` cho Rate Limit) và ghi đầy đủ vào Audit Log.
3. **Môi trường Production & CI (`test/test_check/test_gateway_common.py` — 14 TCs):**
   - An toàn 100%, không gửi payload phá hoại. Kiểm tra cấu hình `config.enterprise.yaml` bật đầy đủ `jwtAuth`, `ui.policies.oidc`, `mcpAuthorization`, `localRateLimit`, CORS chặt và không hardcode key tĩnh.

---

## 2. Ma Trận 60 Test Cases Kiểm Thử Bảo Mật

### Nhóm 1: Hardening Cấu Hình & Smoke Check Production (`SEC-CFG-01` → `SEC-CFG-14` — 14 TCs)
*Thực thi tại: `test/test_check/test_gateway_common.py`*

| Mã TC | Tên kịch bản kiểm thử | Kiểm tra cụ thể | Kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **SEC-CFG-01** | Hợp lệ cú pháp cấu hình YAML | Đọc và parse `config.yaml` và `config.enterprise.yaml`. | Cả 2 file là YAML mapping hợp lệ và có khối `mcp`. |
| **SEC-CFG-02** | Chế độ API Key nghiêm ngặt (`strict`) | Kiểm tra `llm.policies.apiKey.mode` trong `config.enterprise.yaml`. | Giá trị bắt buộc là `"strict"`. |
| **SEC-CFG-03** | Không chứa khóa tĩnh hay API Key thật hardcoded | Quét `providers[*].params.apiKey` và `apiKey.keys[*].key` trong `config.enterprise.yaml`. | Không có key bắt đầu bằng `"sk-"` hay `"agw_sk_"` (phải dùng `$ENV_VAR`). |
| **SEC-CFG-04** | Bắt buộc kích hoạt `mcp.policies.jwtAuth` | Kiểm tra `jwtAuth.issuer`, `audiences`, `jwks.url`. | Đã bật `jwtAuth` và cấu hình đầy đủ JWKS. |
| **SEC-CFG-05** | Bắt buộc bật `mcpAuthorization.rules` | Kiểm tra danh sách luật CEL trong `config.enterprise.yaml`. | Danh sách `rules` tồn tại và có ít nhất 1 quy tắc. |
| **SEC-CFG-06** | Bắt buộc bật giới hạn lưu lượng (`localRateLimit`) | Kiểm tra `mcp.policies.localRateLimit`. | Tồn tại cấu hình `maxTokens` > 0 để chống flood DB. |
| **SEC-CFG-07** | Hạn chế CORS Origins & phơi bày `Mcp-Session-Id` | Kiểm tra `mcp.policies.cors`. | `allowOrigins` không chứa `"*"` ở Production và có `Mcp-Session-Id` trong `exposeHeaders`. |
| **SEC-CFG-08** | Bắt buộc kích hoạt `ui.policies.oidc` | Kiểm tra cấu hình đăng nhập SSO cho Admin UI. | Có `issuer`, `clientId`, `clientSecret: $UI_OIDC_CLIENT_SECRET`. |
| **SEC-CFG-09** | Smoke Check CEL: Cho phép đúng `tenant_id` | Đánh giá `tenant_id == jwt.tenant_id` với `101 == 101`. | Trả về `True`. |
| **SEC-CFG-10** | Smoke Check CEL: Chặn sai `tenant_id` | Đánh giá `tenant_id == jwt.tenant_id` với `999 != 101`. | Trả về `False`. |
| **SEC-CFG-11** | Smoke Check CEL: Chặn khi thiếu trường `tenant_id` | Gọi `get_record` không truyền `tenant_id`. | `has(mcp.tool.arguments.tenant_id)` trả về `False`. |
| **SEC-CFG-12** | Smoke Check CEL: Kiểm tra danh sách trắng Tool | Đánh giá `mcp.tool.name in ["list_resources", "get_metadata"]`. | Trả về `True` với tool hợp lệ, `False` với tool lạ. |
| **SEC-CFG-13** | Smoke Check CEL: Chặn truy vấn bảng nhạy cảm (không phân biệt hoa-thường) | Đánh giá `.lowerAscii().contains("system.users")` với `SYSTEM.USERS`. | Trả về `False` với cả chữ thường lẫn chữ HOA. |
| **SEC-CFG-14** | Smoke Check CEL: Quyền ngoại lệ cho Admin | Đánh giá rule kết hợp `jwt.role == "admin" || (...)`. | User có `role="admin"` được phép (`True`). |

---

### Nhóm 2: Xác Thực Chữ Ký JWT & Chống Giả Mạo Định Danh (`SEC-AUTH-01` → `SEC-AUTH-10` — 10 TCs)
*Thực thi tại: `test/unit_test/test_security_dev.py` (`test_01` → `test_10`)*

| Mã TC | Tên kịch bản kiểm thử | Đầu vào / Tình huống | Kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **SEC-AUTH-01** | Xác thực & trích xuất JWT ký HS256 hợp lệ | Header `Bearer <HS256-signed-jwt>` chứa `sub`, `customer_id`, `role`, `exp`. | Xác thực chữ ký thành công và trả về toàn bộ claims. |
| **SEC-AUTH-02** | Thiếu hoàn toàn Header `Authorization` | Header là `None`. | Trả về `{}` an toàn. |
| **SEC-AUTH-03** | Header là chuỗi rỗng hoặc khoảng trắng | Header `""` hoặc `"   "`. | Trả về `{}` an toàn. |
| **SEC-AUTH-04** | Dùng sai scheme xác thực (`Basic` thay vì `Bearer`) | Header `"Basic YWRtaW46MTIz"`. | Bỏ qua và trả về `{}`. |
| **SEC-AUTH-05** | Chỉ gửi chữ `Bearer` không kèm token | Header `"Bearer"` hoặc `"Bearer   "`. | Trả về `{}`. |
| **SEC-AUTH-06** | Token không đủ cấu trúc 3 phần JWT | `"Bearer abcdef12345"`. | Trả về `{}`. |
| **SEC-AUTH-07** | Token bị sửa đổi làm hỏng mã hóa Base64 | `"Bearer hdr.!!!corrupted!!!.sig"`. | Trả về `{}`. |
| **SEC-AUTH-08** | Payload JWT là mảng JSON hoặc chuỗi thay vì Object | Payload giải mã ra `["admin"]` hoặc `"str"`. | Bị từ chối và trả về `{}`. |
| **SEC-AUTH-09** | Từ chối token dùng thuật toán `alg: "none"` (CVE Bypass) | Token không ký hoặc header sửa thành `{"alg": "none"}`. | Bị từ chối và trả về `{}`. |
| **SEC-AUTH-10** | Từ chối token bị sửa chữ ký hoặc đã hết hạn (`exp`) | Token sửa payload/chữ ký hoặc có `exp` trong quá khứ. | Kiểm tra HMAC/hạn dùng phát hiện sai lệch và trả về `{}`. |

---

### Nhóm 3: Chống Xem Trộm Dữ Liệu Chéo Khách Hàng / IDOR (`SEC-IDOR-01` → `SEC-IDOR-10` — 10 TCs)
*Thực thi tại: `test/unit_test/test_security_dev.py` (`test_11` → `test_20`)*

| Mã TC | Tên kịch bản kiểm thử | Tình huống giả lập tấn công | Kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **SEC-IDOR-01** | Khách hàng A truy vấn đúng mã của mình | `jwt.customer_id="101"`, `params.customer_id="101"`. | Cho phép (`True`). |
| **SEC-IDOR-02** | Prompt Injection ép đổi sang mã khách hàng B | `jwt.customer_id="101"`, `params.customer_id="999"`. | Chặn (`False`). |
| **SEC-IDOR-03** | Bỏ qua hoàn toàn đối tượng `params` | Chỉ gửi `query`, không có khóa `params`. | Chặn (`False`). |
| **SEC-IDOR-04** | Gửi `params: {}` (Object rỗng) | Có `params` nhưng thiếu `customer_id`. | Chặn (`False`). |
| **SEC-IDOR-05** | Truyền giá trị `null` cho `customer_id` | `params: {"customer_id": null}`. | Chặn (`False`). |
| **SEC-IDOR-06** | Truyền chuỗi rỗng `""` cho `customer_id` | `jwt.customer_id=""` hoặc `params.customer_id=""`. | Chặn (`False`). |
| **SEC-IDOR-07** | Tấn công nhầm lẫn kiểu dữ liệu (Type Confusion) | `jwt.customer_id="101"` nhưng gửi `101` (Integer) hoặc `True`. | Chặn (`False`). |
| **SEC-IDOR-08** | Truy cập nặc danh (JWT rỗng `{}`) | Cả `jwt` rỗng và gửi `params.customer_id="101"`. | Chặn (`False`). |
| **SEC-IDOR-09** | Cô lập đa tầng (`org_id` + `customer_id` cùng khớp) | `org_id="ent"` và `customer_id="101"` đều khớp JWT. | Cho phép (`True`). |
| **SEC-IDOR-10** | Lạm dụng cùng tổ chức (`org_id` khớp, `customer_id` khác) | Cùng `org_id="ent"` nhưng xem trộm `customer_id="102"`. | Chặn (`False`). |

---

### Nhóm 4: Chống Prompt Injection, Phá Hoại SQL & RBAC/ABAC (`SEC-INJ-01` → `SEC-INJ-14` — 14 TCs)
*Thực thi tại: `test/unit_test/test_security_dev.py` (`test_21` → `test_34`)*

| Mã TC | Tên kịch bản kiểm thử | Payload / Điều kiện kiểm tra | Kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **SEC-INJ-01** | Truy vấn bảng hệ thống `system.users` (chữ thường & chữ HOA) | Query chứa `system.users` hoặc `SYSTEM.USERS`. | Chặn (`False`) nhờ `.lowerAscii()`. |
| **SEC-INJ-02** | Dò quét bảng `system.grants` / `system.processes` | Query chứa `SYSTEM.GRANTS` hoặc `system.processes`. | Chặn (`False`). |
| **SEC-INJ-03** | Chèn lệnh xóa bảng `DROP TABLE` (mọi kiểu viết hoa/thường) | `DROP TABLE orders` hoặc `DrOp TaBlE orders`. | Chặn (`False`). |
| **SEC-INJ-04** | Chèn lệnh xóa dữ liệu `TRUNCATE` hoặc `DELETE FROM` | `truncate table orders` / `delete from orders`. | Chặn (`False`). |
| **SEC-INJ-05** | Chèn lệnh sửa cấu trúc `ALTER TABLE` | `alter table orders drop column price`. | Chặn (`False`). |
| **SEC-INJ-06** | Cho phép Admin gọi tool quản trị | `jwt.role == "admin"` gọi `admin_tool`. | Cho phép (`True`). |
| **SEC-INJ-07** | Chặn User thường gọi tool quản trị | `jwt.role == "customer"` gọi `admin_tool`. | Chặn (`False`). |
| **SEC-INJ-08** | ABAC: Nhân viên Support hoàn tiền dưới hạn mức (`< 50`) | `jwt.role == "support"` & `amount_usd = 25`. | Cho phép (`True`). |
| **SEC-INJ-09** | ABAC: Chặn Support hoàn tiền vượt hạn mức (`>= 50`) | `jwt.role == "support"` & `amount_usd = 100`. | Chặn (`False`). |
| **SEC-INJ-10** | Ràng buộc tên miền Email nội bộ (`.endsWith`) | Chỉ cho phép email kết thúc bằng `@example.com`. | Đúng đuôi `True`, Gmail bên ngoài `False`. |
| **SEC-INJ-11** | Ràng buộc tiền tố tài khoản (`.startsWith`) | Kiểm tra `jwt.sub.startsWith("ent_")`. | Đúng tiền tố `True`, sai `False`. |
| **SEC-INJ-12** | Kiểm tra phần tử mảng qua chỉ mục (`jwt.groups[0]`) | Kiểm tra nhóm chính trong mảng `groups`. | Khớp `[0]` trả về `True`, ngoài mảng `False`. |
| **SEC-INJ-13** | Xử lý an toàn khi biểu thức CEL sai cú pháp | Truyền biểu thức lỗi `"mcp.tool.name =="`. | Ném `ValueError` rõ ràng (Fail-Closed). |
| **SEC-INJ-14** | Kiểm tra độ ưu tiên ngoặc lồng ghép `||` và `&&` | Kết hợp `admin || (customer && tenant_match)`. | Đánh giá chính xác thứ tự ưu tiên logic. |

---

### Nhóm 5: Kiểm Thử Tích Hợp End-to-End Trên Môi Trường UAT (`SEC-UAT-01` → `SEC-UAT-12` — 12 TCs)
*Thực thi tại: `test/integration_test/test_security_uat.py` (`test_01` → `test_12`)*

| Mã TC | Tên kịch bản kiểm thử trên Server chạy thật | Kịch bản HTTP / MCP | Kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **SEC-UAT-01** | Kiểm tra trạng thái sẵn sàng của Gateway | `GET :15000/healthz/ready` & `GET :3000/healthz/ready`. | Cả 2 cổng đều trả về HTTP `200 OK` (`status: ok`). |
| **SEC-UAT-02** | API Runtime không làm lộ thông tin mật khẩu / secret | `GET :15000/api/runtime`. | Không chứa chuỗi `password`, `secret`, `private_key`, `apiKey`. |
| **SEC-UAT-03** | API CEL Playground đánh giá đúng & bắt lỗi cú pháp | `POST :15000/api/cel` với khớp, lệch và lỗi cú pháp. | Khớp `true`, lệch `false`, sai cú pháp trả `error` (không sập 500). |
| **SEC-UAT-04** | Phiên MCP thật gọi Tool hợp lệ trong Allow-list | `initialize` lấy `Mcp-Session-Id` → gọi `list_databases` qua `:3000/mcp`. | Trả về `200 OK` và danh sách database từ Backend. |
| **SEC-UAT-05** | Chặn tấn công IDOR xem trộm khách hàng khác trên phiên MCP thật | JWT ký HS256 `customer_id="101"` gửi `params.customer_id="999"`. | Gateway chặn ngay: HTTP `403`, JSON-RPC `-32600`. |
| **SEC-UAT-06** | Chặn lách luật bằng cách bỏ trống `params` trên phiên MCP thật | JWT `customer_id="101"` gọi `run_query` không truyền `params`. | Gateway chặn ngay với HTTP `403 Forbidden`. |
| **SEC-UAT-07** | Chặn gọi Tool nhạy cảm khi không gửi hoặc giả mạo JWT Token | Gửi `tools/call` không có token hoặc dùng token `alg:none`. | Gateway chặn ngay với HTTP `403 Forbidden`. |
| **SEC-UAT-08** | Chặn tấn công JSON-RPC Batch (`[{...}]`) | Gửi mảng `[{"jsonrpc":"2.0", "method":"tools/call", ...}]` tới `:3000/mcp`. | Gateway từ chối Fail-Closed với HTTP `400` (`batch requests are not permitted`). |
| **SEC-UAT-09** | Chặn truy vấn bảng `SYSTEM.USERS` (viết HOA lách bộ lọc) | JWT `101` + `params.customer_id="101"` nhưng query chứa `SYSTEM.USERS`. | Gateway chặn ngay với HTTP `403 Forbidden`. |
| **SEC-UAT-10** | Chặn gọi công cụ không nằm trong danh sách cho phép | Gửi lệnh gọi tool lạ `drop_all_databases`. | Gateway chặn ngay với HTTP `403 Forbidden`. |
| **SEC-UAT-11** | Thực thi giới hạn tốc độ (`localRateLimit`) trả về `429` | Bật `maxTokens=2` và gửi 3 request liên tiếp với user test riêng. | Request thứ 3 bị chặn với HTTP `429 Too Many Requests` (`-32029`). |
| **SEC-UAT-12** | Kiểm toán Audit Log & Analytics ghi nhận đủ các vụ chặn `400/403/429` | Truy vấn `POST :15000/api/logs/search` & `/api/logs/analytics/summary`. | Ghi nhận đầy đủ các log chặn `403` của `khach_hang_101` và bộ đếm `errors > 0`. |

---

## 3. Lệnh chạy kiểm thử cho từng môi trường

- **Production / CI (`14 tests`):**
  ```powershell
  python -m unittest discover -s test/test_check -p "test_*.py" -v
  ```
- **Dev (`34 tests`):**
  ```powershell
  python -m unittest discover -s test/unit_test -p "test_*.py" -v
  ```
- **UAT (`12 tests` — yêu cầu Gateway đang chạy tại `:15000` & `:3000`):**
  ```powershell
  python -m unittest discover -s test/integration_test -p "test_*.py" -v
  ```
