#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2013 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/scanners/base'


module Whois
  class Record
    module Scanners

      # Scanner for the whois.comlaude.com record.
      class WhoisComlaudeCom < Base

        self.tokenizers += [
            :skip_empty_line,
            :scan_available,
            :scan_disclaimer,
            :scan_keyvalue,
            :skip_indented_lines,
        ]


        tokenizer :scan_available do
          if @input.skip(/No match for \".*\"./)
            @ast["status:available"] = true
          end
        end

        tokenizer :scan_disclaimer do
          if @input.match?(/^\S([^:]+)\n/)
            @ast["field:disclaimer"] = _scan_lines_to_array(/(.+)\n/).join(" ")
          end
        end

        tokenizer :skip_indented_lines do
          @input.skip(/^\s+.*\n/)
        end

      end

    end
  end
end
