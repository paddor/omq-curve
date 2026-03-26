# frozen_string_literal: true

require "omq"
require "rbnacl"

require_relative "curve/version"
require_relative "z85"
require_relative "zmtp/mechanism/curve"

# Convenience alias: OMQ::Curve.server(...) / OMQ::Curve.client(...)
OMQ::Curve = OMQ::ZMTP::Mechanism::Curve
OMQ::Curve::VERSION = OMQ::CURVE_VERSION
