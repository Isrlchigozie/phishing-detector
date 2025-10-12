"""
Performance visualization for phishing detection system.
Generates charts and visualizations for the project report.
"""

import matplotlib.pyplot as plt
import numpy as np
import json
from datetime import datetime

def create_performance_charts(metrics):
    """Create performance visualization charts."""
    
    # Set up the figure
    plt.figure(figsize=(15, 10))
    
    # Chart 1: Overall Metrics
    plt.subplot(2, 3, 1)
    metrics_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    metrics_values = [
        metrics['accuracy'],
        metrics['precision'], 
        metrics['recall'],
        metrics['f1_score']
    ]
    
    bars = plt.bar(metrics_names, metrics_values, color=['#4361ee', '#4cc9f0', '#f72585', '#7209b7'])
    plt.title('Overall Performance Metrics', fontweight='bold')
    plt.ylim(0, 1)
    
    # Add value labels on bars
    for bar, value in zip(bars, metrics_values):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                f'{value:.1%}', ha='center', va='bottom', fontweight='bold')
    
    # Chart 2: Confusion Matrix Visualization
    plt.subplot(2, 3, 2)
    confusion_matrix = np.array([
        [metrics['true_positives'], metrics['false_negatives']],
        [metrics['false_positives'], metrics['true_negatives']]
    ])
    
    plt.imshow(confusion_matrix, cmap='Blues', interpolation='nearest')
    plt.colorbar()
    plt.xticks([0, 1], ['Phishing', 'Safe'])
    plt.yticks([0, 1], ['Phishing', 'Safe'])
    plt.title('Confusion Matrix', fontweight='bold')
    
    # Add text annotations
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(confusion_matrix[i, j]), 
                    ha='center', va='center', fontweight='bold', fontsize=14,
                    color='white' if confusion_matrix[i, j] > confusion_matrix.max()/2 else 'black')
    
    # Chart 3: Detection by Type
    plt.subplot(2, 3, 3)
    types = ['URL', 'Email']
    accuracies = [metrics['url_accuracy'], metrics['email_accuracy']]
    
    bars = plt.bar(types, accuracies, color=['#2a9d8f', '#e9c46a'])
    plt.title('Accuracy by Content Type', fontweight='bold')
    plt.ylim(0, 1)
    
    for bar, value in zip(bars, accuracies):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                f'{value:.1%}', ha='center', va='bottom', fontweight='bold')
    
    # Chart 4: Error Analysis
    plt.subplot(2, 3, 4)
    errors = ['False Positives', 'False Negatives']
    error_counts = [metrics['false_positives'], metrics['false_negatives']]
    
    plt.pie(error_counts, labels=errors, autopct='%1.1f%%', 
            colors=['#ff9999', '#66b3ff'], startangle=90)
    plt.title('Error Distribution', fontweight='bold')
    
    # Chart 5: Performance Gauge
    plt.subplot(2, 3, 5)
    # Create a simple gauge chart
    theta = np.linspace(0, np.pi, 100)
    r = np.ones(100)
    
    plt.polar(theta, r, color='lightgray')
    performance_angle = metrics['accuracy'] * np.pi
    plt.fill_between(theta[:int(performance_angle * 100/np.pi)], 
                    0, 1, color='green', alpha=0.6)
    plt.title(f'Overall Accuracy: {metrics["accuracy"]:.1%}', fontweight='bold')
    plt.xticks([])
    plt.yticks([])
    
    plt.tight_layout()
    plt.savefig('performance_metrics.png', dpi=300, bbox_inches='tight')
    plt.show()

def main():
    """Load evaluation results and create visualizations."""
    try:
        # Find the latest evaluation report
        import glob
        reports = glob.glob('evaluation_report_*.json')
        if not reports:
            print("No evaluation reports found. Run comprehensive_evaluation.py first.")
            return
        
        latest_report = max(reports)  # Get most recent
        print(f"Loading: {latest_report}")
        
        with open(latest_report, 'r') as f:
            data = json.load(f)
        
        metrics = data['evaluation_report']['summary']
        create_performance_charts(metrics)
        print("✅ Performance charts generated: performance_metrics.png")
        
    except Exception as e:
        print(f"Error generating charts: {e}")

if __name__ == "__main__":
    main()