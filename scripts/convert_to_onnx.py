import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

model = joblib.load('anomaly_model.pkl')

initial_type = [('float_input', FloatTensorType([1, 3]))]

onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    target_opset=12,
    options={id(model): {'zipmap': False}}
)

with open("anomaly_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("✅ Model ONNX'e dönüştürüldü: anomaly_model.onnx")
