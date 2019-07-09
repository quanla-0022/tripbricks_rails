class SessionsController < ApplicationController
  def new; end

  def create
    user = User.find_by email: params[:session][:email].downcase

    if user&.authenticate(params[:session][:password])
      authenticated user
    else
      flash.now[:danger] = t "sign_in_errors"
      render :new
    end
  end

  def destroy
    log_out if logged_in?
    redirect_to root_url
  end

  def authenticated user
    log_in user
    params[:session][:remember_me] == Settings.checked ? remember(user) : forget(user)
    redirect_back_or user
  end
end
