from django.db.models import Q


class StrategyStep(object):
  def __init__(self, strategy, matcher):
    self.strategy = strategy
    self.matcher = matcher

  def get_match_type(self):
    return self.matcher.match_type

  def get_filter(self):
    return (Q(type=self.matcher.vector_type) &
            self.matcher.get_filter())

  def get_source_filter(self):
    return (self.get_filter() &
            self.strategy.get_source_filter())

  def get_target_filter(self):
    return (self.get_filter() &
            self.strategy.get_target_filter())

  def gen_matches(self, source_vectors, target_vectors):
    return self.matcher.match(source_vectors, target_vectors)

  def __repr__(self):
      return "<{}; Matcher={}>".format(self.__class__.__name__,
                                       self.matcher.match_type)


class BinningStrategyStep(StrategyStep):
  def __init__(self, strategy, matcher, min_size, max_size):
    if min_size >= max_size:
      raise ValueError("Invalid bin sizes")

    super(BinningStrategyStep, self).__init__(strategy, matcher)

    self.min_size = min_size
    self.max_size = max_size

  def get_source_filter(self):
    return (super(BinningStrategyStep, self).get_source_filter() &
            Q(instance__size__gte=self.min_size) &
            Q(instance__size__lte=self.max_size))

  def get_target_filter(self):
    return (super(BinningStrategyStep, self).get_target_filter() &
            Q(instance__size__gte=self.min_size) &
            Q(instance__size__lte=self.max_size))
