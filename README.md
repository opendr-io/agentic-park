
![Alt text](img/logo-3.png)
# agentic-park
A park where AI autonomous agent projects live

Contents: 

SMITH: a sort of wingman agent pack that looks for strange things happening in an IDE. It processes event and alert data from the ODR (open DR) project (also in this GitHub org) and outputs an analysis of each alert. It lets you know when it thinks it has a high confidence detection and engages you in a collaborative analysis conversation in order to work out whether the detected activity is benign and expected or unexpected and potentially malicious. 

Usage: install the moduels in requirements.txt, populate a key in the .env file and run:

```python orchestrator.py```