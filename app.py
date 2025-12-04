from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import pickle
from tensorflow.keras.models import load_model
import threading
import time

app = Flask(__name__)

# -----------------------------
# 1. Load model and scaler
# -----------------------------
model = load_model('lstm_cicids_model.h5')
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# -----------------------------
# 2. Feature List
# -----------------------------
features = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s', 'Fwd IAT Mean', 'Bwd IAT Mean',
    'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count', 'FIN Flag Count', 'RST Flag Count', 'URG Flag Count'
]

flows = {}
flow_buffer = []  # mature flows for anomaly table
all_flows = []    # all flows for captured flow details

# ============================================================== #
# 3. Update Flow
# ============================================================== #
def update_flow(pkt):
    if not IP in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    key = (src, dst)
    ts = time.time()
    length = len(pkt)

    if key not in flows:
        flows[key] = {
            'SrcIP': src, 'DstIP': dst,
            'Destination Port': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'Flow Start': ts, 'Last Seen': ts,
            'Fwd Times': [ts], 'Bwd Times': [],
            'Fwd Lengths': [length], 'Bwd Lengths': [],
            'SYN Flag Count': 0, 'ACK Flag Count': 0, 'PSH Flag Count': 0,
            'FIN Flag Count': 0, 'RST Flag Count': 0, 'URG Flag Count': 0
        }
    else:
        flow = flows[key]
        flow['Last Seen'] = ts

        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        if dport == flow['Destination Port']:
            flow['Fwd Times'].append(ts)
            flow['Fwd Lengths'].append(length)
        else:
            flow['Bwd Times'].append(ts)
            flow['Bwd Lengths'].append(length)

        if TCP in pkt:
            flags = pkt[TCP].flags
            flow['SYN Flag Count'] += bool(flags & 0x02)
            flow['ACK Flag Count'] += bool(flags & 0x10)
            flow['PSH Flag Count'] += bool(flags & 0x08)
            flow['FIN Flag Count'] += bool(flags & 0x01)
            flow['RST Flag Count'] += bool(flags & 0x04)
            flow['URG Flag Count'] += bool(flags & 0x20)

# ============================================================== #
# 4. Finalize Flow (Stability + False Positive Reduction)
# ============================================================== #
def finalize_flow(key):
    flow = flows.pop(key, None)
    if not flow:
        return

    start, end = flow['Flow Start'], flow['Last Seen']
    duration = end - start if end > start else 1e-6

    fwd_len = np.array(flow['Fwd Lengths'])
    bwd_len = np.array(flow['Bwd Lengths']) if flow['Bwd Lengths'] else np.array([0])
    fwd_iat = np.diff(flow['Fwd Times']) if len(flow['Fwd Times']) > 1 else np.array([0])
    bwd_iat = np.diff(flow['Bwd Times']) if len(flow['Bwd Times']) > 1 else np.array([0])

    flow_data = {
        'SrcIP': flow['SrcIP'],
        'DstIP': flow['DstIP'],
        'Destination Port': flow['Destination Port'],
        'Flow Duration': max(duration, 1e-6),
        'Total Fwd Packets': len(flow['Fwd Lengths']),
        'Total Backward Packets': len(flow['Bwd Lengths']),
        'Total Length of Fwd Packets': fwd_len.sum(),
        'Total Length of Bwd Packets': bwd_len.sum(),
        'Fwd Packet Length Max': fwd_len.max(),
        'Fwd Packet Length Min': fwd_len.min(),
        'Fwd Packet Length Mean': fwd_len.mean(),
        'Bwd Packet Length Max': bwd_len.max(),
        'Bwd Packet Length Min': bwd_len.min(),
        'Bwd Packet Length Mean': bwd_len.mean(),
        'Flow Bytes/s': np.clip((fwd_len.sum() + bwd_len.sum()) / duration, 0, 1e7),
        'Flow Packets/s': np.clip((len(flow['Fwd Lengths']) + len(flow['Bwd Lengths'])) / duration, 0, 1e5),
        'Fwd IAT Mean': fwd_iat.mean(),
        'Bwd IAT Mean': bwd_iat.mean(),
        'SYN Flag Count': flow['SYN Flag Count'],
        'ACK Flag Count': flow['ACK Flag Count'],
        'PSH Flag Count': flow['PSH Flag Count'],
        'FIN Flag Count': flow['FIN Flag Count'],
        'RST Flag Count': flow['RST Flag Count'],
        'URG Flag Count': flow['URG Flag Count']
    }

    # -----------------------------
    # 1. Always store for captured flow table
    # -----------------------------
    all_flows.append(flow_data)
    if len(all_flows) > 300:
        all_flows.pop(0)

    # -----------------------------
    # 2. Only add mature flows to anomaly table
    # -----------------------------
    total_pkts = flow_data['Total Fwd Packets'] + flow_data['Total Backward Packets']
    if total_pkts >= 5 and flow_data['Flow Duration'] > 0.05:
        # Clamp extreme values
        flow_data['Flow Bytes/s'] = np.clip(flow_data['Flow Bytes/s'], 0, 5e6)
        flow_data['Flow Packets/s'] = np.clip(flow_data['Flow Packets/s'], 0, 5e4)
        # Add to mature flow buffer
        flow_buffer.append(flow_data)
        if len(flow_buffer) > 300:
            flow_buffer.pop(0)

# ============================================================== #
# 5. Cleanup Thread
# ============================================================== #
def cleanup_flows():
    while True:
        now = time.time()
        expired = [k for k, f in flows.items() if now - f['Last Seen'] > 3.0]
        for k in expired:
            finalize_flow(k)
        time.sleep(2)

threading.Thread(target=cleanup_flows, daemon=True).start()

# ============================================================== #
# 6. Packet Sniffer
# ============================================================== #
def packet_sniffer():
    sniff(prn=update_flow, store=False)

threading.Thread(target=packet_sniffer, daemon=True).start()

# ============================================================== #
# 7. Routes
# ============================================================== #
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/flows')
def get_flows():
    if not flow_buffer:
        return jsonify([])

    df = pd.DataFrame(flow_buffer)
    X = np.nan_to_num(df[features].values.astype(np.float32))
    X_scaled = scaler.transform(X)
    X_scaled = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))

    preds = model.predict(X_scaled, batch_size=64, verbose=0)
    df['Confidence'] = preds.flatten().clip(0, 1)

    # Increase threshold slightly to reduce false positives
    df['Anomaly'] = np.where(df['Confidence'] > 0.7, "Normal", "Anomalous (Simulated)")

    return jsonify(df[['SrcIP', 'DstIP', 'Anomaly']].tail(20).to_dict(orient='records'))

@app.route('/stats')
def get_stats():
    if not all_flows:
        return jsonify([])

    df = pd.DataFrame(all_flows)
    X = np.nan_to_num(df[features].values.astype(np.float32))
    X_scaled = scaler.transform(X)
    X_scaled = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))

    preds = model.predict(X_scaled, batch_size=64, verbose=0)
    df['Confidence'] = preds.flatten().clip(0, 1)
    df['Anomaly'] = np.where(df['Confidence'] > 0.7
                             , "Normal", "Anomalous (Simulated)")

    # Return last 20 flows for captured flow table
    return jsonify(df.tail(20).to_dict(orient='records'))

# ============================================================== #
# 8. Run App
# ============================================================== #
if __name__ == '__main__':
    app.run(debug=True)
