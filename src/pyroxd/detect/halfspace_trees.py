"""Streaming Half-Space Trees (HST) -- the flagship anomaly detector.

Implementation of:

    S.C. Tan, K.M. Ting, T.F. Liu, "Fast Anomaly Detection for Streaming
    Data", IJCAI 2011, pp. 1511-1516.

Half-Space Trees are a one-class, *constant time and constant memory*
anomaly detector built for evolving data streams -- exactly the regime of
real-time intrusion detection, where the full dataset is never available and
the traffic distribution drifts over time. No labels are required: the model
learns the shape of "normal" and scores how isolated a new point is.

How it works, in brief:

* An ensemble of ``n_trees`` random binary trees is built *once*, up front,
  over a randomised "work space" that contains the unit hypercube. Each
  internal node splits a randomly chosen dimension at the midpoint of that
  node's current range. The *structure* never changes after construction --
  only per-node mass counters do. That is what makes updates O(depth).
* Mass is accumulated in two interleaved windows of size ``window`` (psi in
  the paper): a frozen *reference* profile ``r`` used for scoring, and a
  *latest* profile ``l`` being filled. Every ``window`` points the latest
  profile replaces the reference and a fresh latest profile begins. This is
  how the model adapts to concept drift without retraining.
* A point's anomaly score comes from the reference mass along its root-to-leaf
  path: dense (normal) regions carry high mass, so we invert the mass sum into
  an anomaly score where *higher means more anomalous*.

Everything is vectorised over the tree ensemble with numpy; there is no
third-party ML dependency.
"""

from __future__ import annotations

import numpy as np


class HalfSpaceTrees:
    """An ensemble of streaming Half-Space Trees.

    Parameters
    ----------
    dim:
        Dimensionality of the incoming feature vectors.
    n_trees:
        Number of trees in the ensemble (``t`` in the paper). More trees give a
        smoother score at linear cost.
    depth:
        Maximum tree depth (``h``). The paper notes accuracy is robust to this;
        15 is a good default for low-dimensional flow features.
    window:
        Window size ``psi``: how many points define one mass profile before the
        reference profile is refreshed. Smaller windows adapt faster to drift.
    size_limit:
        Mass below which descent stops during scoring (the paper's
        ``sizeLimit``); prevents over-crediting sparse deep nodes. Defaults to
        ``0.1 * window``.
    seed:
        RNG seed for reproducible tree construction (tests rely on this).
    """

    def __init__(
        self,
        dim: int,
        n_trees: int = 25,
        depth: int = 15,
        window: int = 250,
        size_limit: float | None = None,
        seed: int | None = None,
    ) -> None:
        if dim <= 0:
            raise ValueError("dim must be positive")
        self.dim = dim
        self.n_trees = n_trees
        self.depth = depth
        self.window = window
        self.size_limit = 0.1 * window if size_limit is None else size_limit
        self._rng = np.random.default_rng(seed)

        # Number of nodes in a complete binary tree of this depth. Node 0 is the
        # root; children of node i are 2i+1 and 2i+2. Storing the ensemble as
        # flat arrays keeps scoring branch-free and cache-friendly.
        self._n_nodes = (1 << (depth + 1)) - 1
        self._internal = (1 << depth) - 1  # indices [0, _internal) are internal

        # Per-node split dimension and split value, one row per tree.
        self._split_dim = np.zeros((n_trees, self._n_nodes), dtype=np.int64)
        self._split_val = np.zeros((n_trees, self._n_nodes), dtype=np.float64)
        # Reference and latest mass counters.
        self._mass_ref = np.zeros((n_trees, self._n_nodes), dtype=np.float64)
        self._mass_lat = np.zeros((n_trees, self._n_nodes), dtype=np.float64)

        self._build_forest()

        self._seen = 0            # points folded into the current latest window
        self._reference_ready = False

    # ------------------------------------------------------------------ build
    def _build_forest(self) -> None:
        """Construct every tree's random structure over a randomised work space.

        For each tree and dimension we pick ``s ~ U(0, 1)`` and set the work
        range to ``[s - 2*m, s + 2*m]`` with ``m = max(s, 1 - s)`` (Tan et al.,
        Sec. 3.1). This range is guaranteed to contain [0, 1] and randomises the
        partitioning across trees. We then recurse, splitting the chosen
        dimension at the midpoint of the node's current range.
        """
        for t in range(self.n_trees):
            s = self._rng.random(self.dim)
            m = np.maximum(s, 1.0 - s)
            work_min = s - 2.0 * m
            work_max = s + 2.0 * m
            self._build_node(t, 0, 0, work_min.copy(), work_max.copy())

    def _build_node(
        self, t: int, node: int, node_depth: int,
        rng_min: np.ndarray, rng_max: np.ndarray,
    ) -> None:
        if node_depth >= self.depth:
            return  # leaf: no split stored
        q = int(self._rng.integers(self.dim))
        mid = (rng_min[q] + rng_max[q]) / 2.0
        self._split_dim[t, node] = q
        self._split_val[t, node] = mid

        left, right = 2 * node + 1, 2 * node + 2
        # Left child inherits [min, mid] on dimension q; right inherits [mid, max].
        lmax = rng_max.copy()
        lmax[q] = mid
        rmin = rng_min.copy()
        rmin[q] = mid
        self._build_node(t, left, node_depth + 1, rng_min, lmax)
        self._build_node(t, right, node_depth + 1, rmin, rng_max)

    # ------------------------------------------------------------------ paths
    def _paths(self, x: np.ndarray) -> np.ndarray:
        """Return, for every tree, the node indices on ``x``'s root->leaf path.

        Shape ``(n_trees, depth + 1)``. Because the forest shares one geometry
        per tree we walk all trees in lockstep with vectorised comparisons.
        """
        paths = np.zeros((self.n_trees, self.depth + 1), dtype=np.int64)
        current = np.zeros(self.n_trees, dtype=np.int64)  # all at root
        trees = np.arange(self.n_trees)
        for d in range(self.depth):
            paths[:, d] = current
            dims = self._split_dim[trees, current]
            vals = self._split_val[trees, current]
            go_right = x[dims] >= vals
            current = np.where(go_right, 2 * current + 2, 2 * current + 1)
        paths[:, self.depth] = current
        return paths

    # ---------------------------------------------------------------- update
    def update(self, x: np.ndarray) -> None:
        """Fold one point into the latest mass profile and roll windows."""
        paths = self._paths(x)
        trees = np.arange(self.n_trees)[:, None]
        # Accumulate mass at every node on the path (not just the leaf): the
        # score uses internal-node mass, so every node on the way down counts.
        np.add.at(self._mass_lat, (trees, paths), 1.0)

        self._seen += 1
        if self._seen >= self.window:
            # Window boundary: promote latest to reference, start a fresh latest.
            self._mass_ref = self._mass_lat
            self._mass_lat = np.zeros_like(self._mass_ref)
            self._seen = 0
            self._reference_ready = True

    def score(self, x: np.ndarray) -> float:
        """Anomaly score for ``x`` from the reference profile; higher = weirder.

        The paper's mass score ``Score(x) = sum over path of r(node) * 2^depth``
        is large in dense regions. During descent we stop crediting deeper nodes
        once a node's reference mass falls below ``size_limit``. We then invert
        and log-compress it into an anomaly score so that sparse (isolated)
        points -- the anomalies -- score high.
        """
        if not self._reference_ready:
            # Before the first reference window closes we cannot judge; abstain.
            return 0.0

        paths = self._paths(x)
        trees = np.arange(self.n_trees)
        depths = np.arange(self.depth + 1, dtype=np.float64)
        weight = 2.0 ** depths  # 2^depth per the paper's mass weighting

        total_mass = 0.0
        for t in trees:
            node_mass = self._mass_ref[t, paths[t]]
            # Stop descent at the first node whose mass dips below size_limit:
            # everything beyond it is treated as part of that sparse region.
            below = node_mass < self.size_limit
            if below.any():
                cutoff = int(np.argmax(below)) + 1
            else:
                cutoff = self.depth + 1
            total_mass += float(np.sum(node_mass[:cutoff] * weight[:cutoff]))

        # Mean mass per tree; +1 avoids log(0). Invert: low mass -> high anomaly.
        mean_mass = total_mass / self.n_trees
        return -np.log1p(mean_mass)

    def score_and_update(self, x: np.ndarray) -> float:
        s = self.score(x)
        self.update(x)
        return s
