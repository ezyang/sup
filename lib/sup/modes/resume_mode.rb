module Redwood

class ResumeMode < EditMessageMode
  def initialize m
    @m = m
    @safe = false

    header, body = parse_file m.draft_filename
    header.delete "Date"

    super :header => header, :body => body, :have_signature => true
  rescue Errno::ENOENT
    DraftManager.discard @m
    BufferManager.flash "Draft deleted outside of sup."
  end

  def unsaved?; !@safe end

  def killable?
    return true if @safe

    case BufferManager.ask_yes_or_no "Discard draft?"
    when true
      DraftManager.discard @m
      BufferManager.flash "Draft discarded."
      true
    when false
      if edited?
        DraftManager.write_draft(Person.from_address(@header["From"]).email) { |f| write_message f, false }
        DraftManager.discard @m
        BufferManager.flash "Draft saved."
      end
      true
    else
      false
    end
  end

  def send_message
    if super
      DraftManager.discard @m
      @safe = true
    end
  end

  def save_as_draft
    DraftManager.write_draft(Person.from_address(@header["From"]).email) { |f| write_message f, false }
    DraftManager.discard @m
    BufferManager.kill_buffer buffer
    BufferManager.flash "Saved for later editing."
  end
end

end
