# Design Choices

## Crow
- Crow is used as a minimal REST API layer. It is lightweight with no unnecessary features which reduces attack vectors. 
- By sticking with a C++ tool we keep all the memory advantages of modern C++.
- While it does not provide some of the advanced middleware like FastAPI or Django we can run it behind a nginx reserve proxy to provide similar security. The idea is that the hardened reverse proxy provides protection while all external interaction is constrained and monitored. 


