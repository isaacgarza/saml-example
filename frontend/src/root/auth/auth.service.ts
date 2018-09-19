import {Injectable} from '@angular/core';
import {Endpoints} from '../../constants/endpoints';
import {Observable} from 'rxjs/Observable';
import {HttpClient} from '@angular/common/http';
import {IUser} from '../../interfaces/user';

@Injectable()
export class AuthService {

  constructor(private http: HttpClient) {}

  static login() {
    window.location.href = Endpoints.LOGIN_API;
  }

  public getUserRole(): Observable<IUser> {
    return this.http.get<IUser>(Endpoints.USER_ROLE_API);
  }
}
