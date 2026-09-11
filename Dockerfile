FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data

EXPOSE 9899

ENV HOST=0.0.0.0
ENV PORT=9899

CMD ["python", "app.py"]
