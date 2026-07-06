use ort::{Session, inputs};
use ndarray::Array1;
use std::path::Path;

pub struct AIModel {
    session: Session,
}

impl AIModel {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let model_path = Path::new("/usr/local/bin/models/anomaly_model.onnx");
        if !model_path.exists() {
            eprintln!("⚠️ UYARI: ONNX model dosyası bulunamadı: {:?}", model_path);
        }
        let session = Session::builder()?
            .with_model_from_file(model_path)?;
        Ok(Self { session })
    }

    pub fn predict(&self, aim_speed: f32, accuracy: f32, reaction_time: f32) -> Result<f32, Box<dyn std::error::Error>> {
        let input_data = Array1::from_vec(vec![aim_speed, accuracy, reaction_time]);
        let input = input_data.into_shape((1, 3))?;
        
        let outputs = self.session.run(inputs![input.view()]?)?;
        let score = outputs[0].try_extract::<f32>()?[0];
        Ok(score)
    }

    pub fn is_suspicious(&self, score: f32) -> bool {
        score > 0.8
    }
}
