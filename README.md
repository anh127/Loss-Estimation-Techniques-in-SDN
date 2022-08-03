# Loss-Estimation-Techniques-in-SDN
The thesis programs network applications for the RYU controller by Python programming language to control and manage functional networks. Devices in the SDN network are simulated by using Mininet - a Linux-based emulator.

## About this thesis
SDN  is a new generation of networks with high potential for development and applicability in the future. SDN provides superior capabilities and flexibility in network control and management. Therefore, SDN is a potential approach to mitigate the challenges of monitoring network traffic. The network monitoring process with accurate results will assist in rerouting traffic, promptly errors recovery, and ensuring the required quality of service.

Fault detection and accurate loss estimation are a part of important requirements in ensuring the reliability of network monitoring. The packet loss rate in each link will provide the necessary information for the network administrator to perform the appropriate tasks.

However, the current methods of estimating packet loss encounter many probles with accuracy and performance in many different network conditions. Therefore, to ensure the required quality of the system and service, flexibility in choosing methods is needed to get the best results.

The thesis proposes and deploys 3 different packet measurement methods, based on the obtained results to evaluate and compare techniques in error detection and packet loss estimation.

## Simulation Description
  - Use the `Topology.py` file to create a model network simulation.
  
  Command use to run the model network simulation:
    `sudo python Topology.py`
  
  Command use to run the application of estimation packet loss:
    `sudo ryu-manager (name of application file) --observe-links`
  
  ### All methods are shown in application files below:

  - **Method of using probing packet - Active Probing:**

    - In the system where is no actual traffic:

      + Run file `Active_Probing.py`: the program does the estimation.
      + Run file `Create_Probe_Packet.py`: simulate probe traffic.

    - In the system where have actual network traffic:

      + Run file `Active_Probing_with_basetraffic.py`: program of estimation.
      + Run file `Create_Probe_Packet.py`: simulate probe traffic.
      + Run file `Base-Traffic-for-ActiveProbing.py`: simulate actual network traffic, with speed adjustment.


  - **Method of using periodic counter - Legacy Counter:**

    + Run file `Legacy_Counter.py`: program estimation.
    + Run file `Send_Packet.py`: simulate actual network traffic, with speed adjustment.


  - **Method of using sampling-based counters - Sampling-based Packet:**

    + Run the file `Sampling_Packet.py`: the program that performs the estimation.
    + Run file `Send_Packet.py`: simulate actual network traffic, with speed adjustment.
