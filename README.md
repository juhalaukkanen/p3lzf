# p3lzf
Rewritten to Python 3 from liblzf3.6.

This one should be more readable than the C implementation lzf_c.c.

Benefits:

-fully compatible bitstream to liblzf 3.6

-you can use unlzf to extract files compressed with this lzf_compress.py

-offers same or in some cases better compression ratio!

-more understandable algorithm

Drawbacks, to develop even further:

-definitely slower compression rate than the C implementation lzf (version 3.6)

-the design is yet at best level: things could be done even higher level with better understanding what is going on
