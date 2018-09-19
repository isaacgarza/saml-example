import {NgModule} from '@angular/core';
import {RootComponent} from './root.component';
import {RootRoutingModule} from './root-routing.module';
import {BrowserModule} from '@angular/platform-browser';
import {LoginModule} from '../login/login.module';
import {AppModule} from '../app/app.module';
import {AuthGuard} from './auth/auth.guard';
import {AuthService} from './auth/auth.service';
import {LoginGuard} from '../login/login.guard';
import {AppService} from "../app/app.service";

@NgModule({
  declarations: [RootComponent],
  imports: [
    BrowserModule,
    RootRoutingModule,
    LoginModule,
    AppModule
  ],
  providers: [AuthGuard, AuthService, LoginGuard, AppService],
  bootstrap: [RootComponent]
})
export class RootModule { }
