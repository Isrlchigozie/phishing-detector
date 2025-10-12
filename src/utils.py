import json
import pickle
import numpy as np
from datetime import datetime

class PhishingUtils:
    """
    Utility functions for the phishing detection system.
    
    Provides common functionality needed across multiple modules:
    - File I/O operations
    - Data formatting
    - Result processing
    - Risk calculation
    """
    
    @staticmethod
    def save_results(results, filename):
        """Save analysis results to JSON file for logging and analysis."""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Convert numpy types to Python native types for JSON serialization
                def convert_types(obj):
                    if isinstance(obj, (np.integer, np.floating)):
                        return float(obj)
                    elif isinstance(obj, np.ndarray):
                        return obj.tolist()
                    elif isinstance(obj, datetime):
                        return obj.isoformat()
                    return obj
                
                json.dump(results, f, indent=2, default=convert_types, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving results: {e}")
            return False
    
    @staticmethod
    def load_model(model_path):
        """Load pre-trained model from file."""
        try:
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error loading model: {e}")
            return None
    
    @staticmethod
    def prepare_features_for_model(features, feature_names):
        """Prepare features for model prediction by ensuring correct order and format."""
        feature_vector = []
        for name in feature_names:
            feature_vector.append(features.get(name, 0))
        return np.array(feature_vector).reshape(1, -1)
    
    @staticmethod
    def get_timestamp():
        """Get current timestamp for logging and results."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def calculate_risk_level(confidence):
        """Calculate risk level based on confidence score."""
        if confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM" 
        elif confidence >= 0.4:
            return "LOW"
        else:
            return "VERY LOW"
    
    @staticmethod
    def format_result_for_display(result):
        """Format analysis result for user-friendly display."""
        formatted = {
            'input': result.get('input', 'Unknown'),
            'type': result.get('type', 'unknown'),
            'is_phishing': result.get('is_phishing', False),
            'confidence': f"{result.get('confidence', 0):.1%}",
            'risk_level': result.get('risk_level', 'UNKNOWN'),
            'explanation': result.get('explanation', 'No explanation available.'),
            'timestamp': result.get('timestamp', 'Unknown')
        }
        return formatted
    
    @staticmethod
    def get_risk_color(risk_level):
        """Get color code for risk level (for UI display)."""
        colors = {
            'HIGH': '#dc3545',      # Red
            'MEDIUM': '#ffc107',    # Yellow  
            'LOW': '#28a745',       # Green
            'VERY LOW': '#17a2b8'   # Blue
        }
        return colors.get(risk_level, '#6c757d')  # Default gray