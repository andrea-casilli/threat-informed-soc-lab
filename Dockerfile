FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY soc_lab ./soc_lab
COPY detection_engine ./detection_engine
COPY parsers ./parsers
RUN pip install --no-cache-dir . && useradd --system --uid 10001 soclab
USER soclab
ENTRYPOINT ["python", "-m", "soc_lab"]
