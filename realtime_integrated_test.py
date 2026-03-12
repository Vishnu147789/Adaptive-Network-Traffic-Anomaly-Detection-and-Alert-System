# Integration of Attack Generator with Real-Time Detector for Live Testing

## Overview
This integration aims to combine the attack generator with the real-time detector in order to facilitate live testing of the anomaly detection functionality. The integration provides a seamless flow of attack generation and real-time monitoring of network traffic anomalies.

## Implementation Steps
1. **Initialize Components**: Start by initializing both the attack generator and the real-time detector components.
2. **Attack Generation Loop**: Create a loop where the attack generator feeds synthetic attack patterns into the network.
3. **Real-Time Detection**: As attacks are generated, capture live network traffic and process it using the real-time detector.
4. **Logging & Monitoring**: Implement logging to track generated attacks and detect anomalies.
5. **Feedback Mechanism**: Establish a feedback loop to analyze detection results and adjust the attack parameters accordingly.

## Example Code
```python
import time
from attack_generator import AttackGenerator
from real_time_detector import RealTimeDetector

# Initialize the components
attack_generator = AttackGenerator()
real_time_detector = RealTimeDetector()

# Start live testing
try:
    while True:
        # Generate an attack
        attack = attack_generator.generate_attack()
        print(f"Generated Attack: {attack}")

        # Simulate the attack on the network
        attack_generator.simulate_attack(attack)

        # Detect in real-time
        anomalies = real_time_detector.detect_anomalies()
        if anomalies:
            print(f"Anomalies Detected: {anomalies}")
        else:
            print("No anomalies detected.")

        # Sleep before the next iteration
        time.sleep(1)  # adjust the sleep time as necessary

except KeyboardInterrupt:
    print("Live testing stopped.")
