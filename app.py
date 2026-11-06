import os
import logging
import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

# 1. Xác định đường dẫn thư mục gốc và tải các biến môi trường từ file .env
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

# 2. Khởi tạo ứng dụng Flask
app = Flask(__name__)

# 3. Cấu hình logging để ghi nhận lỗi ở phía Backend (API Key, Network, v.v.)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("WeatherMiniApp")

# Hằng số cấu hình OpenWeatherMap API
OPENWEATHER_API_URL = "https://api.openweathermap.org/data/2.5/weather"
REQUEST_TIMEOUT = 10  # Thời gian chờ tối đa (giây) khi gọi API bên ngoài


@app.route("/", methods=["GET"])
def index():
    """
    Route chính trả về giao diện trang chủ Bảng Thời Tiết Mini.
    """
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    """
    Endpoint Health Check phục vụ bước kiểm thử Container trong DevSecOps Pipeline.
    """
    return jsonify({"status": "healthy", "version": "1.0"}), 200


@app.route("/api/weather", methods=["GET"])
def get_weather():
    """
    Endpoint API nhận tên thành phố từ query string (?city=...)
    và truy vấn dữ liệu thời tiết hiện tại từ OpenWeatherMap.
    """
    # Lấy tham số 'city' từ URL và loại bỏ khoảng trắng thừa ở hai đầu
    city = request.args.get("city", "").strip()

    # Kiểm tra đầu vào: Không cho phép chuỗi rỗng
    if not city:
        return jsonify({
            "error": "Vui lòng nhập tên thành phố hoặc khu vực cần tra cứu!"
        }), 400

    # Đọc lại file .env (override=True) để nhận ngay API Key mới nếu vừa cập nhật file .env
    load_dotenv(ENV_PATH, override=True)
    api_key = os.getenv("OPENWEATHER_API_KEY", "").strip()

    # Kiểm tra xem API Key đã được cấu hình hợp lệ hay chưa
    if not api_key or api_key == "your_openweather_api_key_here":
        logger.error("OPENWEATHER_API_KEY chưa được cấu hình hoặc vẫn đang để giá trị mặc định trong file .env.")
        return jsonify({
            "error": "Hệ thống chưa được cấu hình API Key thời tiết. Vui lòng kiểm tra lại cấu hình trên máy chủ!"
        }), 500

    # Thiết lập tham số gọi OpenWeatherMap Current Weather Data API
    # Sử dụng units='metric' để nhận trực tiếp nhiệt độ theo độ C (°C)
    # Sử dụng lang='vi' để nhận mô tả tình trạng thời tiết bằng tiếng Việt
    params = {
        "q": city,
        "appid": api_key,
        "units": "metric",
        "lang": "vi",
    }

    try:
        logger.info("Đang truy vấn thời tiết cho thành phố: '%s'", city)
        response = requests.get(OPENWEATHER_API_URL, params=params, timeout=REQUEST_TIMEOUT)

        # Trường hợp 1: Người dùng nhập sai tên thành phố (OpenWeatherMap trả về 404)
        if response.status_code == 404:
            logger.warning("Không tìm thấy thành phố: '%s' (HTTP 404)", city)
            return jsonify({
                "error": "Không tìm thấy thành phố, vui lòng thử lại!"
            }), 404

        # Trường hợp 2: Lỗi xác thực API Key (OpenWeatherMap trả về 401)
        if response.status_code == 401:
            logger.error("Xác thực OpenWeatherMap thất bại (HTTP 401): API Key không hợp lệ hoặc chưa được kích hoạt.")
            return jsonify({
                "error": "Không thể xác thực dịch vụ thời tiết (Lỗi API Key). Vui lòng thử lại sau!"
            }), 500

        # Trường hợp 3: Vượt quá giới hạn request hoặc các lỗi HTTP khác từ phía OpenWeatherMap
        if response.status_code != 200:
            logger.error(
                "Lỗi từ OpenWeatherMap API (HTTP %s): %s",
                response.status_code,
                response.text,
            )
            return jsonify({
                "error": "Dịch vụ thời tiết hiện đang gặp sự cố. Vui lòng thử lại sau ít phút!"
            }), 500

        # Phân tích dữ liệu JSON trả về khi thành công (HTTP 200)
        data = response.json()

        # Trích xuất và chuẩn hóa dữ liệu cần thiết cho Frontend
        weather_info = data.get("weather", [{}])[0]
        main_info = data.get("main", {})
        wind_info = data.get("wind", {})
        sys_info = data.get("sys", {})

        icon_code = weather_info.get("icon", "01d")
        description = weather_info.get("description", "Không rõ")

        result = {
            "city": data.get("name", city),
            "country": sys_info.get("country", ""),
            "temperature": round(main_info.get("temp", 0), 1),
            "feels_like": round(main_info.get("feels_like", 0), 1),
            "temp_min": round(main_info.get("temp_min", 0), 1),
            "temp_max": round(main_info.get("temp_max", 0), 1),
            "humidity": main_info.get("humidity", 0),
            "pressure": main_info.get("pressure", 0),
            "wind_speed": wind_info.get("speed", 0),
            "description": description.capitalize(),
            "condition_main": weather_info.get("main", ""),
            "icon": icon_code,
            "icon_url": f"https://openweathermap.org/img/wn/{icon_code}@4x.png",
        }

        return jsonify(result), 200

    except requests.exceptions.Timeout:
        # Bắt lỗi quá thời gian chờ phản hồi từ server OpenWeatherMap
        logger.error("Timeout khi kết nối tới OpenWeatherMap API cho thành phố '%s'.", city)
        return jsonify({
            "error": "Kết nối đến máy chủ thời tiết bị quá thời gian chờ. Vui lòng kiểm tra mạng và thử lại!"
        }), 500

    except requests.exceptions.ConnectionError as conn_err:
        # Bắt lỗi mất kết nối mạng hoặc DNS
        logger.error("Lỗi kết nối mạng khi gọi OpenWeatherMap API: %s", conn_err)
        return jsonify({
            "error": "Không thể kết nối đến dịch vụ thời tiết. Vui lòng kiểm tra kết nối Internet!"
        }), 500

    except requests.exceptions.RequestException as req_err:
        # Bắt tất cả các ngoại lệ khác của thư viện requests
        logger.error("Lỗi RequestException khi gọi OpenWeatherMap API: %s", req_err)
        return jsonify({
            "error": "Đã xảy ra lỗi khi lấy dữ liệu thời tiết. Vui lòng thử lại sau!"
        }), 500

    except Exception as exc:
        # Bắt các lỗi hệ thống không lường trước
        logger.exception("Lỗi nội bộ không xác định tại /api/weather: %s", exc)
        return jsonify({
            "error": "Đã xảy ra lỗi hệ thống nội bộ. Vui lòng thử lại sau!"
        }), 500


if __name__ == "__main__":
    # Đặt debug=False để tuân thủ chuẩn bảo mật SAST (Semgrep) trong DevSecOps Pipeline
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosemgrep
