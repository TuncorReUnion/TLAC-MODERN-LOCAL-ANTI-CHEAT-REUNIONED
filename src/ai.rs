use tract_onnx::prelude::*;
use std::path::Path;

pub struct AIModel
{
    model: tract_onnx::prelude::SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>,
}

impl AIModel
{
    pub fn new() -> Result<Self, Box<dyn std::error::Error>>
    {
        let model_path = Path::new("/usr/local/bin/models/anomaly_model.onnx");
        if !model_path.exists()
        {
            eprintln!("⚠️ UYARI: ONNX model dosyası bulunamadı: {:?}", model_path);
        }
        let model = tract_onnx::onnx()
        .model_for_path(model_path)?
        .into_optimized()?
        .into_runnable()?;
        Ok(Self { model })
    }

    pub fn predict(&self, aim_speed: f32, accuracy: f32, reaction_time: f32) -> Result<f32, Box<dyn std::error::Error>>
    {
        let input_data = vec![aim_speed, accuracy, reaction_time];
        let tensor = Tensor::from_shape(&[1, 3], input_data)?;

        let result = self.model.run(tvec!(tensor))?;

        let score = result[0].to_scalar::<f32>()?;
        Ok(*score)
    }

    pub fn is_suspicious(&self, score: f32) -> bool
    {
        score > 0.8
    }
}
