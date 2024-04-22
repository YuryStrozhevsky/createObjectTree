# Basic information
This project is all about composing full "object tree list" for arbitrary ActiveDirectory element. Then the "object tree list" is using in access checking routine _AuthzAccessCheck_. All the code is on piure C++ using _winldap_ functions, smart pointers, smart deleters and so on. 

The path for target ActiveDirectory element is set via _target_dn_ variable inside _check_ function.

# License
(c) 2024, Yury Strozhevsky
[yury@strozhevsky.com](mailto:yury@strozhevsky.com)

Anyone allowed to do whatever he/she want with the code.