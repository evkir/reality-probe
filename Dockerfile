FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY realityprobe/ realityprobe/
COPY reality_probe.py .

ENV RP_HOST=0.0.0.0 RP_PORT=7890 RP_NO_BROWSER=1
EXPOSE 7890

CMD ["python", "-m", "realityprobe"]
