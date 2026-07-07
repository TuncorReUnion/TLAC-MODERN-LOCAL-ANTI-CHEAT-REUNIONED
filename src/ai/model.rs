use tract_onnx::prelude::*;
use std::path::Path;

pub struct AnomalyDetector
{
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
}

impl AnomalyDetector
{
    pub fn new(model_path: &str) -> Result<Self, Box<dyn std::error::Error>>
    {
        let model = tract_onnx::onnx()
        .model_for_path(Path::new(model_path))?
        .into_optimized()?
        .into_runnable()?;

        Ok(Self { model })
    }

    pub fn predict(&self, features: [f32; 5]) -> Result<f32, Box<dyn std::error::Error>>
    {
        let input = tract_ndarray::Array1::from_vec(features.to_vec());
        let result = self.model.run(tvec!(input.into()))?;

        Ok(result[0].to_scalar::<f32>()?.clone())
    }
}
