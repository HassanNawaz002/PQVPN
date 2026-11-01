
"""Sliding-window anti-replay tracking for authenticated packets."""


class ReplayWindow:
    def __init__(self, window_size=1024):
        if not isinstance(window_size, int) or not (
            1 <= window_size <= 65536
        ):
            raise ValueError("Invalid replay window size")

        self.window_size = window_size
        self.highest = -1
        self.bitmap = 0
        self.mask = (1 << window_size) - 1

    def can_accept(self, sequence):
        if not isinstance(sequence, int) or not (
            0 <= sequence < (1 << 64)
        ):
            return False

        if self.highest == -1 or sequence > self.highest:
            return True

        offset = self.highest - sequence

        if offset >= self.window_size:
            return False

        return not bool(self.bitmap & (1 << offset))

    def mark_authenticated(self, sequence):
        """Call only after AEAD authentication succeeds."""

        if not self.can_accept(sequence):
            return False

        if self.highest == -1:
            self.highest = sequence
            self.bitmap = 1
            return True

        if sequence > self.highest:
            shift = sequence - self.highest

            if shift >= self.window_size:
                self.bitmap = 0
            else:
                self.bitmap = (
                    self.bitmap << shift
                ) & self.mask

            self.bitmap |= 1
            self.highest = sequence
        else:
            offset = self.highest - sequence
            self.bitmap |= 1 << offset

        return True
