FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data

EXPOSE 8899

ENV HOST=0.0.0.0
ENV PORT=8899

CMD ["python", "app.py"]
