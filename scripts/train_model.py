import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

data = pd.DataFrame({
    'aim_speed': np.array([0.5, 0.6, 0.4, 0.9, 1.2, 0.3, 0.7, 1.1, 0.45, 0.55, 0.95, 1.15], dtype=np.float32),
    'accuracy': np.array([0.7, 0.8, 0.6, 0.95, 0.98, 0.5, 0.75, 0.97, 0.65, 0.85, 0.93, 0.99], dtype=np.float32),
    'reaction_time': np.array([200, 210, 190, 50, 30, 220, 205, 40, 195, 215, 55, 25], dtype=np.float32),
    'is_cheater': np.array([0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1], dtype=np.int64)
})

X = data[['aim_speed', 'accuracy', 'reaction_time']]
y = data['is_cheater']

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

joblib.dump(model, 'anomaly_model.pkl')
print("✅ Model eğitildi ve kaydedildi: anomaly_model.pkl")
