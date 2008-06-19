require File.dirname(__FILE__) + '/spec_helper'

describe "merb_doorman DSL" do
  include Merb::Plugins::Doorman

  before(:each) do
    @_doorman_list = nil
  end

  it "should store the ACL" do
    _doorman_list.should be_an_instance_of(Array)
  end
  
  it "should have an implicit allow :all" do
    _doorman_list.should have(1).element
    _doorman_list.first.should eql(:all)
  end
  
  it "should have a deny method" do
    lambda { deny :all }.should_not raise_error
  end
  
  it "should store a deny entry on the ACL" do
    s = _doorman_list.size
    deny :host => "192.168.*"
    _doorman_list.should have(s + 1).elements
  end
  
  it "should have an allow method" do
    lambda { allow :all }.should_not raise_error
  end
  
  it "should store an allow entry on the ACL" do
    s = _doorman_list.size
    allow :user_agent => /MSIE/
    _doorman_list.should have(s + 1).elements
  end
  
  it "should allow valid ACL entries" do
    lambda { deny :host => "192.168.*" }.should_not raise_error
    lambda { deny :user => "bill" }.should_not raise_error
    lambda { deny :user_agent => /MSIE/ }.should_not raise_error
    lambda { deny :time => "8am-5pm" }.should_not raise_error
    lambda { deny {|c| c.foo } }.should_not raise_error
  end
  
  it "should reject invalid ACL entries" do
    lambda { deny :foo => "3" }.should raise_error
    lambda { deny { foo } }.should raise_error
  end
end

# deny :host => "209.34.*"
# deny :user => "bill"       # calls current_user.login, but this is configurable
# deny :user_agent => /MSIE/
# deny {|c| c.params["arbitrary"] == "expressions"}
# 
# 
# # mostly closed:
# deny :all                           # removes implicit final allow :all
# allow :host => "*.example.com"
# allow :time => "8am-5pm"
# 
# # store a block for repeated usage
# Merb::Access.add_block :admin, {|c| c.current_user.admin?}
# 
# allow :admin