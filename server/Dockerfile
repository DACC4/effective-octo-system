FROM python:3.12-slim

WORKDIR /app

COPY main.py main.py

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt && pip3 install gunicorn

VOLUME [ "/app/data" ]
EXPOSE 4242

CMD [ "gunicorn", "-w 1", "-b 0.0.0.0:4242", "main:app" ]
