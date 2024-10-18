# Use the official Python image as the base image
FROM python:3.13

# Set the working directory in the container
WORKDIR /app

# Copy the application files into the working directory
COPY . /app

# Install the application dependencies
RUN pip install -r requirements.txt

# Define the entry point for the container
CMD ["gunicorn", "--workers", "1", "--threads", "1", "app:app", "--max-requests", "5", "--max-requests-jitter", "2"]

