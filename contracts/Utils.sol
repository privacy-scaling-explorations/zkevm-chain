contract Utils {
  /// @dev Revert if caller is not tx sender.
  /// Thus, we make sure that only regular accounts can submit blocks.
  function _onlyEOA () internal view {
    assembly {
      if iszero(eq(origin(), caller())) {
        revert(0, 0)
      }
    }
  }
}
