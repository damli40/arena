# Design credit (for the README)

The paper hunter's design follows **AutoRedTeamer: Autonomous Red Teaming with Lifelong Attack
Integration** by Andy Zhou, Kevin Wu, Francesco Pinto, Zhaorun Chen, Yi Zeng, Yu Yang, Shuang Yang,
Sanmi Koyejo, James Zou and Bo Li (NeurIPS 2025, [arXiv 2503.15754](https://arxiv.org/abs/2503.15754)).
We adapted four of its ideas to a bench for payment guards. We copied no code.

1. **Score papers before attacking.** Each candidate paper gets a score for novelty, distance from
   the attacks we already have, and the attack success it reports. The model's budget goes to the
   top-scored papers first.
2. **Validate before adding.** A new attack joins the library only after it runs cleanly on every
   guard in the sandbox. It is recorded as "broke a guard" or "valid but nothing broke".
3. **Combine attacks.** The model may join the core ideas of two or more library attacks, such as
   a race plus an expired invoice. These are marked as combined and list their parents.
4. **Remember what works.** A record of attack × guard results over time decides what runs next:
   attacks never tried on a guard, and kinds of attack that broke a guard before. This is how the
   library keeps the attacks that work.

One deliberate difference: in AutoRedTeamer the model writes new attacks as code. Here the model
writes data only, in a fixed list of step types the harness already knows, so nothing it writes
is ever executed.
