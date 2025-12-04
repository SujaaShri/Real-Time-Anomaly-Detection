# Real Time etwork Traffic Anomaly Detection
This project builds a deep-learning-based network anomaly detection system using CICIDS dataset that identifies abnormal traffic patterns in real time. Unlike traditional IDS approaches that rely on predefined attack signatures, this system detects anomalies by learning the normal behavior of network flows and flagging deviations automatically.


# Model Overview

## Flow details:

Single-flow: Each flow processed independently

Multi-flow: Sequential windows of flows processed as a temporal pattern

## Channel Design:

Features are encoded as multi-channel vectors (e.g., packet size, duration, flags, bytes, inter-arrival times)

Model treats each feature as a channel similar to multi-channel time-series input

## Architecture:

Lightweight CNN + BiLSTM hybrid network

CNN extracts short-range flow patterns

BiLSTM models long-range temporal dependencies

## Output:

Score indicating normal vs anomalous behavior

Threshold tuned using validation statistics (mean + k·std)


# Training & Evaluation

Dataset normalized with MinMax scaling

Trained only on normal traffic (unsupervised anomaly detection)

Validation includes synthetic and real-world anomalies

Metrics: Precision, Recall, F1-score, ROC-AUC
