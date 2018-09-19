import {CanActivate, Router} from '@angular/router';
import {Observable} from 'rxjs/Observable';
import {Injectable} from '@angular/core';
import {AuthService} from '../root/auth/auth.service';
import {HttpErrorResponse} from '@angular/common/http';

@Injectable()
export class LoginGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {
  }

  canActivate(): Observable<boolean> {
    return this.authService.getUserRole().map(
      userAuthority => {
        if (userAuthority.role === 'ROLE_ADMIN') {
          this.router.navigate(['/']);
          return false;
        } else {
          return true;
        }
      },
      error => this.handleError(error));
  }

  handleError(err: HttpErrorResponse) {
    // in a real world root, we may send the server to some remote logging infrastructure
    // instead of just logging it to the console
    console.error('Error retrieving User');
    let errorMessage = '';
    if (err.error instanceof Error) {
      // A client-side or network error occurred. Handle it accordingly.
      errorMessage = `An error occurred: ${err.error.message}`;
    } else {
      // The backend returned an unsuccessful response code.
      // The response body may contain clues as to what went wrong,
      errorMessage = `Server returned code: ${err.status}, error message is: ${err.message}`;
    }
    console.error(errorMessage);
    return Observable.throw(errorMessage);
  }
}
