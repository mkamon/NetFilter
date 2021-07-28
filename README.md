# IPv4 filtering algorithm for L3/L4 signature

The NetFilter purpose is to enforce L3/L4 rules to network traffic.  

Please notice that two separate solutions are provided (as both solution were a lot of fun to do):
* QuickFilter (the solution - if one should be chosen)
* NetFilter (solution submitted as the first, then replaced with the QuickFilter)

The difference between the two is fundamental and it lies in the approach:
* QuickFilter focuses on minimizing steps that need to be computed to find filtering `Rule`s and the amount of filtering `Rule`s
  themselves that need to be verified to accept or deny a single packet.
* NetFilter focuses on the traffic itself with three following optimizations:
    - caching of rejected packets metadata - simple method to deal with overflowing packets that are invalid
    - caching of rules that recently caused a packet to be accepted - this approach
      is useful to deal with big data transfers (file transferring, streaming, videoconferences),
      high demands of resources (e.g. popular websites)
    - prioritizing highly versatile and often used `Rule`s by simple self-learning algorithm with memory - if
      a `Rule` is responsible for acceptance of large portion of packets in the past, it should be check first as there is high probability,
      it will accept packets it the future.
    

