# Real-Time Network Traffic Anomaly Detection

This project implements a deep-learning-based system using the CICIDS dataset to classify network traffic as Normal or Anomalous in real time. Instead of relying on predefined attack signatures, it detects anomalies by learning patterns in normal traffic and flagging deviations automatically.


# Model Overview
## Flow Details:

Multi-flow: Sequential windows of flows processed as a temporal pattern

## Channel Design:

Features are encoded as multi-channel vectors (e.g., packet counts, lengths, inter-arrival times, TCP/UDP flags)
Each feature is treated as a separate channel in the input to the LSTM model

## Architecture:

Lightweight LSTM-based network with dropout and L2 regularization
Captures temporal dependencies in network flows for anomaly detection

## Output:

Binary classification: Normal vs Anomalous
Confidence score provided per flow; threshold applied to reduce false positives

## Training & Evaluation

Dataset balanced across classes and normalized using StandardScaler
Early stopping used to prevent overfitting
Metrics: Accuracy, Loss, Precision, Recall, F1-score
Trained and tested on CICIDS flows; capable of real-time anomaly prediction via Flask web interface
