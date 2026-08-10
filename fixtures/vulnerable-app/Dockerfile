# Faille infra: image de base non epinglee par digest, conteneur en root.
FROM python:3.11

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

# Faille infra: aucun utilisateur non-root, secret passe en build arg.
ARG WEBHOOK_SECRET
ENV WEBHOOK_SECRET=$WEBHOOK_SECRET

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
