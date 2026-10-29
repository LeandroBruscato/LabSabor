FROM python:3.12-slim
WORKDIR /app
COPY app.py index.html ./
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
