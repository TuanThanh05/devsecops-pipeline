``` yaml  
  <tên-job>:
    name: "<Tên hiển thị>"
    runs-on: ubuntu-latest
    needs: [<job phải xanh trước>]      # bỏ dòng này nếu là tầng 1 hoặc nếu có

    steps:
      # ---------- 1. CHUẨN BỊ ----------
      - name: Checkout code
        uses: actions/checkout@v4

      # ---------- 2. QUÉT & GHI BÁO CÁO (không chặn) ----------
      - name: Scan <tên hiển thị> by <tên công cụ>
        ...                              # xuất ra file, KHÔNG fail

      # ---------- 3. CỔNG CHẶN ----------
      - name: "gate-<tên hiển thị>"
        ...                              # exit code 1 khi vi phạm

      # ---------- 4. LƯU BÁO CÁO (luôn chạy) ----------
      - name: <tên hiển thị> Scan Report
        if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: <tên-job>-report
          path: <tên file báo cáo>
```